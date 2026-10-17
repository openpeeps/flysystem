#
# Secure path resolution for flysystem's local drivers.
#
# (c) 2026 George Lemon | MIT License
#     Made by Humans from OpenPeeps
#     https://github.com/openpeeps/flysystem
#
## TOCTOU-proof containment for POSIX local drivers.
##
## String-based checks ("resolve, compare, then operate") always leave a
## check-use gap: the filesystem can change between the comparison and the
## operation. This module removes the gap by making resolution and opening the
## same act. Every component of a path is opened with `openat` through a held
## parent file descriptor, so the descriptor you end up holding was obtained
## through a chain of verified parents. There is no later step to redirect.
##
## Rules enforced by the walk:
## - `openat` is only ever called with a single plain component. `..`, `.`,
##   `/` and empty components never reach a syscall: `..` is resolved
##   lexically with clamping at the root, and anything that would leave the
##   root raises before any descriptor is opened.
## - Every `openat` carries `O_NOFOLLOW`, so a symlink fails loudly with
##   `ELOOP` instead of being followed silently.
## - Following happens only deliberately: on `ELOOP` the target is read with
##   `readlinkat` (one level, like `std/symlinks`), absolute targets are
##   refused outright, and relative targets are spliced into the remaining walk
##   which restarts from the root descriptor. A link budget of 40 bounds cycles.
##   A symlink is therefore followed if and only if its resolved target stays
##   inside the attached drive.
## - The root itself is canonicalized at construction, because on macOS even
##   `/tmp` is a symlink; comparing resolved candidates against an unresolved
##   root would reject everything legitimate.
##
## Two entry points exist because some operations act *on the link itself*:
## resolving the final component unconditionally would make `delete(link)`
## remove the link's *target* and break `readLink`. `openSecure` resolves
## everything (data operations); `openSecureParent` walks all but the last
## component and returns `(parentFd, basename)` (link operations, creates,
## deletes, renames).
##
## POSIX-only. On other platforms the same procedure names fall back to the
## previous lexical check (`normalizedPath` plus a separator-boundary prefix
## comparison), documented here as weaker: it closes the prefix-confusion hole
## but cannot close symlink or TOCTOU holes without `openat`.

import std/[os, strutils, sequtils, times, algorithm, posix]
import ./core

type
  SandboxError* = object of StorageError
    ## Raised when a path escapes the driver root or a symlink cannot be
    ## resolved inside it. A subtype of `StorageError`, so existing
    ## `except StorageError` handlers are unaffected.
    ##
    ## (SecureRoot itself lives in `core`, next to the driver types that
    ## carry it, to avoid an import cycle.)

const MaxLinks = 40

when defined(posix):
  # Nim's toolchain does not declare these (verified against Nim 2.2 stdlib),
  # so they are bound here following the same `importc` pattern the toolchain
  # itself uses for platform constants.
  proc sjOpenat(dirfd: cint, path: cstring, flags: cint,
      mode: Mode): cint {.importc: "openat", header: "<fcntl.h>".}
  proc sjFstatat(dirfd: cint, path: cstring, buf: var Stat,
      flags: cint): cint {.importc: "fstatat", header: "<sys/stat.h>".}
  proc sjMkdirat(dirfd: cint, path: cstring, mode: Mode): cint {.
      importc: "mkdirat", header: "<sys/stat.h>".}
  proc sjUnlinkat(dirfd: cint, path: cstring, flags: cint): cint {.
      importc: "unlinkat", header: "<fcntl.h>".}
  when defined(macosx):
    proc sjRenameat(olddirfd: cint, oldpath: cstring, newdirfd: cint,
        newpath: cstring): cint {.importc: "renameat", header: "<stdio.h>".}
    proc sjSymlinkat(target: cstring, newdirfd: cint,
        linkpath: cstring): cint {.importc: "symlinkat", header: "<unistd.h>".}
    proc sjReadlinkat(dirfd: cint, path: cstring, buf: cstring,
        bufsiz: int): int {.importc: "readlinkat", header: "<unistd.h>".}
    proc sjFutimens(fd: cint, times: pointer): cint {.
        importc: "futimens", header: "<sys/time.h>".}
  else:
    proc sjRenameat(olddirfd: cint, oldpath: cstring, newdirfd: cint,
        newpath: cstring): cint {.importc: "renameat", header: "<fcntl.h>".}
    proc sjSymlinkat(target: cstring, newdirfd: cint,
        linkpath: cstring): cint {.importc: "symlinkat", header: "<fcntl.h>".}
    proc sjReadlinkat(dirfd: cint, path: cstring, buf: cstring,
        bufsiz: int): int {.importc: "readlinkat", header: "<fcntl.h>".}
    proc sjFutimens(fd: cint, times: pointer): cint {.
        importc: "futimens", header: "<fcntl.h>".}
  proc sjFdopendir(fd: cint): ptr DIR {.importc: "fdopendir",
      header: "<dirent.h>".}
  var sjO_NOFOLLOW* {.importc: "O_NOFOLLOW", header: "<fcntl.h>".}: cint
  var sjO_DIRECTORY* {.importc: "O_DIRECTORY", header: "<fcntl.h>".}: cint
  var sjAT_SYMLINK_NOFOLLOW* {.importc: "AT_SYMLINK_NOFOLLOW",
      header: "<fcntl.h>".}: cint
  var sjAT_REMOVEDIR* {.importc: "AT_REMOVEDIR", header: "<fcntl.h>".}: cint
  var sjS_IROTH* {.importc: "S_IROTH", header: "<sys/stat.h>".}: cint

proc sandboxErr(path: string): ref SandboxError =
  newException(SandboxError, "Path traversal detected: " & path)

template sandboxPassthrough*(op: string, path: string,
    body: untyped): untyped =
  ## Run `body`, letting `SandboxError` through unwrapped (so its
  ## "Path traversal detected: ..." message stays byte-identical for
  ## callers that assert on it) while wrapping anything else with operation
  ## context. Platform-agnostic: on non-POSIX targets the descriptor walk
  ## is unavailable, so callers are expected to use the lexical fallback
  ## (`containedStr`) and plain `std/os` operations inside `body`.
  try: body
  except SandboxError: raise
  except CatchableError as e:
    raise newException(StorageError,
      "Failed to " & op & " '" & path & "': " & e.msg)

proc lexSplit(orig: string): seq[string] =
  ## Split a driver-relative path into plain components, resolving `.` and
  ## clamping `..` at the root. Anything that would leave the root raises
  ## before any descriptor is opened, so `..` can never reach a syscall.
  var depth = 0
  for part in orig.split({DirSep, AltSep}):
    if part.len == 0 or part == ".":
      continue
    if part == "..":
      if depth == 0:
        raise sandboxErr(orig)
      dec depth
      result.setLen(result.len - 1)
    else:
      inc depth
      result.add(part)

proc openSecureRoot*(path: string): SecureRoot =
  ## Open a driver root: create it if missing (matching `newLocalDriver`
  ## behaviour), canonicalize it fully, then hold it open as a directory
  ## descriptor. Everything descended from here starts from this descriptor,
  ## never from a re-parsed string.
  let abs = expandTilde(path).absolutePath
  if not dirExists(abs):
    createDir(abs)
  when defined(posix):
    # Canonicalize through the OS so symlink prefixes (e.g. /tmp on macOS)
    # cannot desynchronize later comparisons.
    let canon =
      try: expandFilename(abs)
      except OSError as e:
        raise newException(StorageError,
          "Failed to open driver root '" & path & "': " & e.msg)
    let fd = posix.open(canon.cstring, O_RDONLY or sjO_DIRECTORY or O_CLOEXEC)
    if fd < 0:
      raise newException(StorageError,
        "Failed to open driver root '" & path & "'")
    SecureRoot(fd: fd, path: canon)
  else:
    SecureRoot(fd: -1, path: abs)

proc closeSecureRoot*(r: var SecureRoot) =
  ## Release the held root descriptor. Drivers live for process lifetime, so
  ## calling this is optional; it exists for embedding and tests.
  when defined(posix):
    if r.fd >= 0:
      discard posix.close(r.fd)
      r.fd = -1

when defined(posix):
  proc errnoCode(): cint =
    osLastError().int.cint

  proc readlinkatStr(dirfd: cint, name: string): string =
    ## Read one level of symlink target, growing the buffer on truncation.
    var size = 256
    while true:
      var buf = newString(size)
      let n = sjReadlinkat(dirfd, name.cstring, buf.cstring, size)
      if n < 0:
        raise newException(StorageError,
          "Failed to read symlink '" & name & "': " & $strerror(errnoCode()))
      if n < size:
        buf.setLen(n)
        return buf
      size = size * 2

  proc spliceTarget(prefix: seq[string], target: string,
      rest: seq[string], orig: string): seq[string] =
    ## Splice a relative symlink target into the remaining walk. `..` inside
    ## the target is clamped against the already-consumed logical prefix, so a
    ## link like `sub/../../etc` cannot smuggle an escape past the restart.
    result = prefix
    var depth = prefix.len
    for part in target.split({DirSep, AltSep}):
      if part.len == 0 or part == ".":
        continue
      if part == "..":
        if depth == 0:
          raise sandboxErr(orig)
        dec depth
        result.setLen(result.len - 1)
      else:
        inc depth
        result.add(part)
    for comp in rest:
      result.add(comp)

  proc openWalk(root: SecureRoot, initial: seq[string], lastFlags: cint,
      mode: Mode, orig: string): cint =
    ## Walk components from a duplicated root descriptor, opening the final one
    ## with `lastFlags`. A symlink anywhere fails with `ELOOP` and is followed
    ## only via readlink + full re-walk with a link budget: each restart
    ## re-verifies the entire chain through held descriptors, so there is no
    ## check-use gap.
    var logical = initial
    var links = 0
    var cur = posix.dup(root.fd)
    if cur < 0:
      raise newException(StorageError, "Failed to duplicate root descriptor")
    var i = 0
    var consumed: seq[string] = @[]
    while i < logical.len:
      let last = i == logical.high
      var flags = if last: lastFlags
                  else: O_RDONLY or sjO_DIRECTORY or O_CLOEXEC
      flags = flags or sjO_NOFOLLOW or O_CLOEXEC
      let fd = sjOpenat(cur, logical[i].cstring, flags, mode)
      if fd >= 0:
        discard posix.close(cur)
        cur = fd
        consumed.add(logical[i])
        inc i
        continue
      let err = errnoCode()
      var isLink = err == ELOOP
      if not isLink and err == ENOTDIR:
        # macOS reports ENOTDIR (not ELOOP) for O_NOFOLLOW|O_DIRECTORY on a
        # link-to-dir. Classify with lstat before deciding: a genuine
        # non-directory must stay an error. The classification itself cannot
        # grant access — either path re-verifies through the walk.
        var st: Stat
        if sjFstatat(cur, logical[i].cstring, st,
            sjAT_SYMLINK_NOFOLLOW) == 0:
          isLink = S_ISLNK(st.st_mode)
      if not isLink:
        discard posix.close(cur)
        if err == ENOENT:
          raise newException(StorageError,
            "No such file or directory: " & orig)
        raise newException(StorageError,
          "Failed to open '" & orig & "': " & $strerror(err))
      inc links
      if links > MaxLinks:
        discard posix.close(cur)
        raise newException(SandboxError,
          "Too many levels of symbolic links: " & orig)
      let target =
        try: readlinkatStr(cur, logical[i])
        except CatchableError as e:
          discard posix.close(cur)
          raise e
      discard posix.close(cur)
      if target.isAbsolute:
        raise sandboxErr(orig)
      let rest = if i + 1 < logical.len: logical[i + 1 .. ^1] else: @[]
      logical = spliceTarget(consumed, target, rest, orig)
      consumed.setLen(0)
      cur = posix.dup(root.fd)
      if cur < 0:
        raise newException(StorageError, "Failed to duplicate root descriptor")
      i = 0
    cur

  proc normalizeInput(root: SecureRoot, relpath: string): seq[string] =
    ## Accept root-relative paths. An absolute input is relativized only when
    ## it lexically names something under the root; anything else is refused.
    ## This classification is for error reporting only — containment itself is
    ## enforced by the descriptor walk regardless.
    if relpath.isAbsolute:
      # Normalize lexically first so `/root/../root/f` classifies the same as
      # `/root/f`. The walk enforces containment regardless; this is only so
      # error classification is stable.
      let norm = normalizedPath(relpath)
      let canon = root.path
      if norm == canon:
        return @[]
      if norm.startsWith(canon & DirSep):
        return lexSplit(norm[canon.len + 1 .. ^1])
      raise sandboxErr(relpath)
    lexSplit(relpath)

  proc openSecure*(root: SecureRoot, relpath: string, flags: cint,
      mode = Mode(0o666)): cint =
    ## Open `relpath` for data access, fully resolved. The returned descriptor
    ## is obtained through verified parents; callers own it and must close it.
    let comps = normalizeInput(root, relpath)
    if comps.len == 0:
      # The root itself: duplicate the held descriptor.
      let fd = posix.dup(root.fd)
      if fd < 0:
        raise newException(StorageError, "Failed to duplicate root descriptor")
      return fd
    openWalk(root, comps, flags, mode, relpath)

  proc openSecureParent*(root: SecureRoot,
      relpath: string): tuple[dirFd: cint, base: string] =
    ## Walk all but the last component and return `(parentFd, basename)`.
    ## The final component is never resolved, so link-acting operations
    ## (`delete`, `readLink`, renames) act on the link itself, never its target.
    let comps = normalizeInput(root, relpath)
    if comps.len == 0:
      raise newException(StorageError,
        "Operation on the driver root itself is not allowed: " & relpath)
    let base = comps[^1]
    if comps.len == 1:
      let fd = posix.dup(root.fd)
      if fd < 0:
        raise newException(StorageError, "Failed to duplicate root descriptor")
      return (fd, base)
    let dirFd = openWalk(root, comps[0 .. ^2],
      O_RDONLY or sjO_DIRECTORY, Mode(0), relpath)
    (dirFd, base)

  proc lstatSecure*(root: SecureRoot,
      relpath: string): tuple[present: bool, st: Stat] =
    ## `lstat` without following the final component: true for symlinks
    ## themselves, false when absent, never raising for either.
    let (dirFd, base) = openSecureParent(root, relpath)
    defer: discard posix.close(dirFd)
    var st: Stat
    if sjFstatat(dirFd, base.cstring, st, sjAT_SYMLINK_NOFOLLOW) != 0:
      if errnoCode() == ENOENT:
        return (false, st)
      raise newException(StorageError,
        "Failed to stat '" & relpath & "': " & $strerror(errnoCode()))
    (true, st)

  proc readAllFd*(fd: cint): string =
    ## Read an open descriptor to exhaustion.
    var buf: array[8192, byte]
    while true:
      let n = posix.read(fd, addr buf[0], buf.len)
      if n < 0:
        raise newException(StorageError, "Failed to read: " & $strerror(errnoCode()))
      if n == 0: break
      let prev = result.len
      result.setLen(prev + n)
      copyMem(addr result[prev], addr buf[0], n)

  proc createFileIn*(dirFd: cint, base: string, mode = Mode(0o666)): cint =
    ## Open `base` in the held `dirFd` for writing, creating or truncating,
    ## never following a symlink. Callers own the descriptor.
    result = sjOpenat(dirFd, base.cstring,
      O_WRONLY or O_CREAT or O_TRUNC or sjO_NOFOLLOW or O_CLOEXEC, mode)
    if result < 0:
      raise newException(StorageError,
        "Failed to open '" & base & "': " & $strerror(errnoCode()))

  proc writeBufFd*(fd: cint, buf: openArray[byte], n: int) =
    ## Write the first `n` bytes of `buf` to `fd`, looping on short writes.
    var off = 0
    while off < n:
      let w = posix.write(fd, unsafeAddr buf[off], n - off)
      if w <= 0:
        raise newException(StorageError,
          "Failed to write: " & $strerror(errnoCode()))
      off += w

  proc writeAllFd*(fd: cint, s: string) =
    ## Write a whole string to an open descriptor.
    var written = 0
    while written < s.len:
      let n = posix.write(fd, unsafeAddr s[written], s.len - written)
      if n <= 0:
        raise newException(StorageError, "Failed to write: " & $strerror(errnoCode()))
      written += n

  proc mmapFd*(fd: cint, size: int): pointer =
    ## Memory-map `size` bytes readable from `fd`.
    result = posix.mmap(nil, size, PROT_READ, MAP_SHARED, fd, 0)
    if result == MAP_FAILED:
      raise newException(StorageError,
        "Failed to mmap: " & $strerror(errnoCode()))

  type
    DirEntry* = tuple[name: string, isDir: bool, size: int64,
      mtime: times.Time]
    StackEntry = tuple[fd: cint, rel: string]

  proc listDirFd*(dirFd: cint): seq[DirEntry] =
    ## Enumerate a verified-open directory without touching path strings:
    ## `fdopendir` takes ownership, so hand it a duplicate and close the stream.
    ## The duplicate shares the file offset with the original, so rewind to 0
    ## first — otherwise a second enumeration of the same descriptor starts at
    ## EOF and spuriously reports an empty directory.
    let dupFd = posix.dup(dirFd)
    if dupFd < 0:
      raise newException(StorageError, "Failed to duplicate descriptor")
    if posix.lseek(dupFd, 0, SEEK_SET) < 0:
      discard posix.close(dupFd)
      raise newException(StorageError,
        "Failed to rewind directory: " & $strerror(errnoCode()))
    let dirp = sjFdopendir(dupFd)
    if dirp == nil:
      discard posix.close(dupFd)
      raise newException(StorageError,
        "Failed to open directory: " & $strerror(errnoCode()))
    defer: discard posix.closedir(dirp)
    while true:
      let ent = posix.readdir(dirp)
      if ent == nil: break
      let name = $cast[cstring](addr ent.d_name[0])
      if name == "." or name == "..":
        continue
      # d_type is advisory; always confirm with fstatat so DT_UNKNOWN
      # platforms behave identically.
      var st: Stat
      if sjFstatat(dirFd, name.cstring, st, sjAT_SYMLINK_NOFOLLOW) != 0:
        continue
      result.add((name, S_ISDIR(st.st_mode), st.st_size.int64,
        fromUnix(st.st_mtime.int64)))

  proc fullMtime*(st: Stat): times.Time =
    ## Full-precision modification time. The second-granularity `st_mtime`
    ## accessor truncates sub-second precision, which breaks `>=` comparisons
    ## against `getTime()` taken just before an operation.
    when StatHasNanoseconds:
      fromUnix(st.st_mtim.tv_sec.int64) +
        initDuration(nanoseconds = st.st_mtim.tv_nsec.int64)
    else:
      fromUnix(int64(st.st_mtime))

  proc statMeta*(relpath: string, st: Stat): FileMetadata =
    ## Build driver metadata from an `fstat` result. Visibility follows the
    ## same rule as before (world-readable bit); symlinks never reach here
    ## with their link identity because callers stat through resolving opens.
    FileMetadata(
      path: relpath,
      size: st.st_size.int64,
      lastModified: fullMtime(st),
      visibility: (if (st.st_mode.int32 and sjS_IROTH) != 0: visPublic
                   else: visPrivate),
      isDir: S_ISDIR(st.st_mode)
    )

  proc fstatFd*(fd: cint): Stat =
    ## `fstat` a held descriptor, raising on failure.
    if posix.fstat(fd, result) != 0:
      raise newException(StorageError,
        "Failed to stat: " & $strerror(errnoCode()))

  var tmpCounter {.threadvar.}: int64

  proc tmpBase*(base: string): string =
    ## A unique sibling name for atomic writes in the same directory, so
    ## `renameat` never crosses filesystems.
    inc tmpCounter
    base & ".tmp" & $getCurrentProcessId() & "." & $tmpCounter

  proc ensureDirsSecure*(root: SecureRoot, relpath: string) =
    ## `mkdir -p` through verified parents. Existing components are fine
    ## (`EEXIST` is not an error); the final component is included, so callers
    ## pass the directory itself, not the file.
    let comps = normalizeInput(root, relpath)
    var cur = posix.dup(root.fd)
    if cur < 0:
      raise newException(StorageError, "Failed to duplicate root descriptor")
    defer: discard posix.close(cur)
    var acc: seq[string] = @[]
    for comp in comps:
      # Each level is opened-or-created through the verified parent, so a
      # racing rename cannot redirect the descent.
      var fd = sjOpenat(cur, comp.cstring,
        O_RDONLY or sjO_DIRECTORY or sjO_NOFOLLOW or O_CLOEXEC, Mode(0))
      if fd < 0:
        if errnoCode() != ENOENT:
          let here = acc & comp
          raise newException(StorageError,
            "Failed to traverse '" & here.join($DirSep) & "': " &
            $strerror(errnoCode()))
        if sjMkdirat(cur, comp.cstring, Mode(0o755)) != 0 and
            errnoCode() != EEXIST:
          raise newException(StorageError,
            "Failed to create directory '" & comp & "': " &
            $strerror(errnoCode()))
        fd = sjOpenat(cur, comp.cstring,
          O_RDONLY or sjO_DIRECTORY or sjO_NOFOLLOW or O_CLOEXEC, Mode(0))
        if fd < 0:
          raise newException(StorageError,
            "Failed to open created directory '" & comp & "': " &
            $strerror(errnoCode()))
      discard posix.close(cur)
      cur = fd
      acc.add(comp)

  proc atomicWriteSecure*(root: SecureRoot, relpath, content: string,
      mode: Mode) =
    ## Write `content` atomically: tmp file in the same directory plus
    ## `renameat`, so a crash mid-write never corrupts the target. Parents are
    ## created first, then the parent is (re-)resolved through the walk, so
    ## every descriptor in play was verified.
    let comps = normalizeInput(root, relpath)
    if comps.len == 0:
      raise newException(StorageError,
        "Cannot write to the driver root itself: " & relpath)
    if comps.len > 1:
      ensureDirsSecure(root, comps[0 .. ^2].join($DirSep))
    let (dirFd, base) = openSecureParent(root, relpath)
    defer: discard posix.close(dirFd)
    let tmp = tmpBase(base)
    let tmpFd = sjOpenat(dirFd, tmp.cstring,
      O_WRONLY or O_CREAT or O_EXCL or sjO_NOFOLLOW or O_CLOEXEC,
      Mode(0o666))
    if tmpFd < 0:
      raise newException(StorageError,
        "Failed to create temp file for '" & relpath & "': " &
        $strerror(errnoCode()))
    try:
      writeAllFd(tmpFd, content)
      if posix.fchmod(tmpFd, mode) != 0:
        raise newException(StorageError, "Failed to set permissions")
    finally:
      discard posix.close(tmpFd)
    if sjRenameat(dirFd, tmp.cstring, dirFd, base.cstring) != 0:
      discard sjUnlinkat(dirFd, tmp.cstring, 0)
      raise newException(StorageError,
        "Failed to rename temp file for '" & relpath & "': " &
        $strerror(errnoCode()))

  proc removeSecure*(root: SecureRoot, relpath: string) =
    ## Remove a file, symlink, or empty directory. Operates on the name itself
    ## (never resolves the final component), so deleting a link removes the
    ## link. A non-empty directory fails, matching `delete` semantics. A missing
    ## path is a silent no-op, matching `delete` idempotency.
    let (dirFd, base) = openSecureParent(root, relpath)
    defer: discard posix.close(dirFd)
    if sjUnlinkat(dirFd, base.cstring, 0) == 0:
      return
    if errnoCode() == ENOENT:
      return
    if sjUnlinkat(dirFd, base.cstring, sjAT_REMOVEDIR) == 0:
      return
    if errnoCode() == ENOENT:
      return
    raise newException(StorageError,
      "Failed to delete '" & relpath & "': " & $strerror(errnoCode()))

  proc normalizeRel*(root: SecureRoot, relpath: string): string =
    ## The canonical driver-relative form of `relpath` (no `.`, no `..`, no
    ## empty segments). Raises exactly like the walk would on escape.
    normalizeInput(root, relpath).join($DirSep)

  proc openTempIn*(dirFd: cint, base: string): tuple[fd: cint, tmp: string] =
    ## Create an exclusive temp file beside `base` in the held `dirFd`.
    let tmp = tmpBase(base)
    let fd = sjOpenat(dirFd, tmp.cstring,
      O_WRONLY or O_CREAT or O_EXCL or sjO_NOFOLLOW or O_CLOEXEC,
      Mode(0o666))
    if fd < 0:
      raise newException(StorageError,
        "Failed to create temp file for '" & base & "': " &
        $strerror(errnoCode()))
    (fd, tmp)

  proc commitTemp*(dirFd: cint, tmp, base: string) =
    ## Atomically rename `tmp` over `base` in the held `dirFd`, cleaning up
    ## the temp file when the rename fails.
    if sjRenameat(dirFd, tmp.cstring, dirFd, base.cstring) != 0:
      let err = errnoCode()
      discard sjUnlinkat(dirFd, tmp.cstring, 0)
      raise newException(StorageError,
        "Failed to rename temp file for '" & base & "': " & $strerror(err))

  proc ensureParentSecure*(root: SecureRoot, relpath: string) =
    ## Ensure the parent directory of `relpath` exists, creating missing
    ## levels through verified parents.
    let comps = normalizeInput(root, relpath)
    if comps.len > 1:
      ensureDirsSecure(root, comps[0 .. ^2].join($DirSep))

  proc copyFileSecure*(root: SecureRoot, srcRel, dstRel: string) =
    ## Copy file content fd-to-fd. A symlinked source is followed transparently
    ## when (and only when) its target resolves inside the drive — the walk
    ## enforces that, so outside content can never be pulled in. This preserves
    ## the previous observable behaviour for the valid case.
    ensureParentSecure(root, dstRel)
    let srcFd = openSecure(root, srcRel, O_RDONLY)
    defer: discard posix.close(srcFd)
    let (dstDir, dstBase) = openSecureParent(root, dstRel)
    defer: discard posix.close(dstDir)
    let dstFd = sjOpenat(dstDir, dstBase.cstring,
      O_WRONLY or O_CREAT or O_TRUNC or sjO_NOFOLLOW or O_CLOEXEC,
      Mode(0o666))
    if dstFd < 0:
      raise newException(StorageError,
        "Failed to open '" & dstRel & "': " & $strerror(errnoCode()))
    defer: discard posix.close(dstFd)
    var buf: array[8192, byte]
    while true:
      let n = posix.read(srcFd, addr buf[0], buf.len)
      if n < 0:
        raise newException(StorageError, "Failed to copy '" & srcRel & "'")
      if n == 0: break
      var off = 0
      while off < n:
        let w = posix.write(dstFd, addr buf[off], n - off)
        if w <= 0:
          raise newException(StorageError, "Failed to copy '" & srcRel & "'")
        off += w


  proc listSecure*(root: SecureRoot, relpath: string,
      recursive: bool): seq[tuple[rel: string, st: Stat]] =
    ## Enumerate `(relative path, lstat)` pairs without any path string
    ## reaching the kernel after the initial walk. Symlinks appear as
    ## themselves (`lstat` semantics); outside-pointing links are listed but
    ## their targets are never traversed.
    let dirFd = openSecure(root, relpath,
      O_RDONLY or sjO_DIRECTORY)
    defer: discard posix.close(dirFd)
    let base = normalizeInput(root, relpath).join($DirSep)
    result = @[]
    let top = posix.dup(dirFd)
    if top < 0:
      raise newException(StorageError, "Failed to duplicate descriptor")
    var stack: seq[StackEntry] = @[(top, base)]
    while stack.len > 0:
      let cur = stack.pop()
      let curFd = cur.fd
      let curRel = cur.rel
      for ent in listDirFd(curFd):
        let rel = if curRel.len == 0: ent.name else: curRel / ent.name
        var st: Stat
        if sjFstatat(curFd, ent.name.cstring, st, sjAT_SYMLINK_NOFOLLOW) != 0:
          continue
        result.add((rel, st))
        if recursive and S_ISDIR(st.st_mode):
          let sub = sjOpenat(curFd, ent.name.cstring,
            O_RDONLY or sjO_DIRECTORY or sjO_NOFOLLOW or O_CLOEXEC, Mode(0))
          # A symlinked directory fails here with ELOOP and is listed but not
          # traversed: its target may lie outside the drive.
          if sub >= 0:
            stack.add((sub, rel))
      discard posix.close(curFd)

  proc renameSecure*(root: SecureRoot, srcRel, dstRel: string) =
    ## Move a file or directory with `renameat`. Both sides are parent-walked;
    ## a symlink is moved as a link (rename never follows), so no content
    ## crosses the boundary in either direction.
    ensureParentSecure(root, dstRel)
    let (srcDir, srcBase) = openSecureParent(root, srcRel)
    defer: discard posix.close(srcDir)
    let (dstDir, dstBase) = openSecureParent(root, dstRel)
    defer: discard posix.close(dstDir)
    if sjRenameat(srcDir, srcBase.cstring, dstDir, dstBase.cstring) != 0:
      raise newException(StorageError, "Failed to move '" & srcRel &
        "' to '" & dstRel & "': " & $strerror(errnoCode()))

  proc removeTreeSecure*(root: SecureRoot, relpath: string) =
    ## Recursively delete a directory tree. Enumeration is fd-based; symlinked
    ## directories are listed but their targets are never traversed, and each
    ## removal names its entry through a held parent descriptor.
    # Delete deepest entries first so directories are empty when removed.
    var entries = listSecure(root, relpath, true)
    entries.sort(proc(a, b: tuple[rel: string, st: Stat]): int =
      cmp(b.rel.len, a.rel.len))
    for (rel, st) in entries:
      let (dirFd, base) = openSecureParent(root, rel)
      if S_ISDIR(st.st_mode):
        if sjUnlinkat(dirFd, base.cstring, sjAT_REMOVEDIR) != 0:
          discard posix.close(dirFd)
          raise newException(StorageError,
            "Failed to delete '" & rel & "': " & $strerror(errnoCode()))
      else:
        if sjUnlinkat(dirFd, base.cstring, 0) != 0:
          discard posix.close(dirFd)
          raise newException(StorageError,
            "Failed to delete '" & rel & "': " & $strerror(errnoCode()))
      discard posix.close(dirFd)
    removeSecure(root, relpath)

  proc copyDirSecure*(root: SecureRoot, srcRel, dstRel: string) =
    ## Recursively copy a directory, including empty directories. Symlinked
    ## files resolve transparently when contained; symlinked directories are
    ## recreated as links only when their target resolves inside the drive,
    ## otherwise the copy fails closed rather than pulling outside content in.
    ensureParentSecure(root, dstRel)
    let srcComps = normalizeInput(root, srcRel)
    let dstComps = normalizeInput(root, dstRel)
    if srcComps.len == 0 or dstComps.len == 0:
      raise newException(StorageError, "Cannot copy the driver root itself")
    ensureDirsSecure(root, dstComps.join($DirSep))
    # `listSecure` returns paths already prefixed with the source base, so
    # strip that prefix to get the part under it — do NOT re-prepend it.
    for (rel, st) in listSecure(root, srcComps.join($DirSep), true):
      let tail = rel.split({DirSep, AltSep})[srcComps.len .. ^1]
      let srcEntry = rel
      let dstEntry = (dstComps & tail).join($DirSep)
      if S_ISDIR(st.st_mode):
        ensureDirsSecure(root, dstEntry)
      else:
        var isLink = false
        block checkLink:
          let (sdir, sbase) = openSecureParent(root, srcEntry)
          defer: discard posix.close(sdir)
          var lst: Stat
          if sjFstatat(sdir, sbase.cstring, lst,
              sjAT_SYMLINK_NOFOLLOW) == 0:
            isLink = S_ISLNK(lst.st_mode)
        if isLink:
          let (sdir, sbase) = openSecureParent(root, srcEntry)
          defer: discard posix.close(sdir)
          let target = readlinkatStr(sdir, sbase)
          # Re-resolve the target against the source tree: only contained
          # targets may be recreated.
          let linkDirRel =
            if srcEntry.split({DirSep, AltSep}).len > 1:
              srcEntry.split({DirSep, AltSep})[0 .. ^2].join($DirSep)
            else: ""
          let resolved =
            if target.isAbsolute: target
            else: (if linkDirRel.len > 0: linkDirRel / target else: target)
          let probe = openSecure(root, resolved, O_RDONLY)
          discard posix.close(probe)
          let (ddir, dbase) = openSecureParent(root, dstEntry)
          defer: discard posix.close(ddir)
          discard sjUnlinkat(ddir, dbase.cstring, 0)
          if sjSymlinkat(target.cstring, ddir, dbase.cstring) != 0:
            raise newException(StorageError,
              "Failed to copy symlink '" & srcEntry & "': " &
              $strerror(errnoCode()))
        else:
          copyFileSecure(root, srcEntry, dstEntry)

  proc symlinkIn*(dirFd: cint, target, base: string) =
    ## Create symlink `base` in the held `dirFd` pointing at `target`.
    if sjSymlinkat(target.cstring, dirFd, base.cstring) != 0:
      raise newException(StorageError,
        "Failed to create symlink '" & base & "': " & $strerror(errnoCode()))

  proc readlinkIn*(dirFd: cint, base: string): string =
    ## Read one level of link target for `base` in the held `dirFd`.
    readlinkatStr(dirFd, base)

  proc checkLexicalContained*(root: SecureRoot, relpath: string) =
    ## Refuse `relpath` unless it lexically names something under the root.
    ## Used where the target need not exist (symlink creation): existence is
    ## irrelevant to the question being asked, which is purely "does this name
    ## stay inside". Absolute inputs must name the root itself or something
    ## under it; anything else raises exactly like the walk would.
    discard normalizeInput(root, relpath)

  proc touchSecure*(root: SecureRoot, relpath: string) =
    ## Create if missing, bump mtime, never truncate.
    ensureParentSecure(root, relpath)
    let (dirFd, base) = openSecureParent(root, relpath)
    defer: discard posix.close(dirFd)
    let fd = sjOpenat(dirFd, base.cstring,
      O_WRONLY or O_CREAT or sjO_NOFOLLOW or O_CLOEXEC, Mode(0o666))
    if fd < 0:
      raise newException(StorageError,
        "Failed to touch '" & relpath & "': " & $strerror(errnoCode()))
    defer: discard posix.close(fd)
    # nil times = set both to now.
    if sjFutimens(fd, nil) != 0:
      raise newException(StorageError,
        "Failed to touch '" & relpath & "': " & $strerror(errnoCode()))
  proc searchSecure*(root: SecureRoot, pattern: string): seq[string] =
    ## Glob match over fd-enumerated relative paths. The pattern is split into
    ## segments and each segment is matched with `fnmatch` (no flags needed:
    ## segments never contain `/`), which mirrors `walkPattern` component
    ## semantics for the documented uses (`*.txt`, `sub/*.log`).
    let (dir, _) = splitPath(pattern)
    let baseComps = if dir.len == 0: @[] else: normalizeInput(root, dir)
    let baseRel = baseComps.join($DirSep)
    let patSegs = pattern.split({DirSep, AltSep}).filterIt(
      it.len > 0 and it != ".")
    var all: seq[string] = @[]
    proc walk(fd: cint, rel: string) =
      for ent in listDirFd(fd):
        let entryRel = if rel.len == 0: ent.name else: rel / ent.name
        all.add(entryRel)
        if ent.isDir:
          let sub = sjOpenat(fd, ent.name.cstring,
            O_RDONLY or sjO_DIRECTORY or sjO_NOFOLLOW or O_CLOEXEC, Mode(0))
          if sub >= 0:
            walk(sub, entryRel)
            discard posix.close(sub)
    let baseFd = openSecure(root, baseRel, O_RDONLY or sjO_DIRECTORY)
    defer: discard posix.close(baseFd)
    walk(baseFd, baseRel)
    for rel in all:
      let relSegs = rel.split({DirSep, AltSep})
      if relSegs.len != patSegs.len:
        continue
      var ok = true
      for i in 0 ..< patSegs.len:
        if posix.fnmatch(patSegs[i].cstring, relSegs[i].cstring, 0) != 0:
          ok = false
          break
      if ok:
        result.add(rel)

else:
  # Non-POSIX fallback: lexical check with a separator boundary. Documented as
  # weaker — it closes prefix confusion but cannot close symlink or TOCTOU
  # holes without openat.
  proc containedStr*(root, candidate: string): bool =
    candidate == root or candidate.startsWith(root & DirSep)
