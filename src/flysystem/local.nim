#
# A filesystem API for Nim, inspired by Flysystem
# from the PHP ecosystem.
#
# (c) 2026 George Lemon | MIT License
#     Made by Humans from OpenPeeps
#     https://github.com/openpeeps/flysystem
import std/[os, strutils, options, times, syncio, posix]
when defined(features.flysystem.useStdStreams):
  import std/streams
else:
  import std/memfiles
import pkg/mimedb
import checksums/md5
import ./core
import ./securejoin

#
# Local Driver implementation
#
# Every operation descends from the held root descriptor via `securejoin`, so
# containment is enforced by construction (see that module): there is no
# resolve-compare-operate gap anywhere in this file.
#

proc newLocalDriver*(root: string): LocalDriver =
  ## Creates a LocalDriver. `root` is an absolute runtime path.
  ## Example: pass in the value of an env var or config key at startup.
  ## The root is canonicalized (symlinks resolved) and held open; `d.root`
  ## always names the canonical location.
  let sroot = openSecureRoot(root)
  result = LocalDriver(root: sroot.path, sroot: sroot)

proc closeDriver*(d: LocalDriver) =
  ## Releases the held root descriptor. Drivers typically live for process
  ## lifetime, so calling this is optional.
  closeSecureRoot(d.sroot)

method write*(d: LocalDriver, path, content: string,
    visibility = visPrivate) =
  ## Writes `content` to the file at `path`. The write is atomic: content is
  ## first written to a temporary file in the same directory and then renamed
  ## over the target, so a crash mid-write never corrupts the file.
  sandboxPassthrough("write", path):
    atomicWriteSecure(d.sroot, path, content,
      if visibility == visPublic: Mode(0o644) else: Mode(0o600))

method read*(d: LocalDriver, path: string): string =
  ## Reads a file from the local filesystem at the specified path.
  ##
  ## The path is resolved against the driver's root directory.
  sandboxPassthrough("read", path):
    let fd = openSecure(d.sroot, path, O_RDONLY)
    defer: discard posix.close(fd)
    readAllFd(fd)

method readStream*(d: LocalDriver, path: string): FlysystemStream =
  ## Efficiently reads a file as a stream.
  ## Default backend uses memfiles (mmap); with `-d:features.flysystem.useStdStreams`
  ## it returns a `Stream` (`StringStream`). An empty file yields an empty
  ## stream that does not need `close` (mmap backend) but must still be closed
  ## for symmetry with the streams backend, which always requires it.
  sandboxPassthrough("read stream", path):
    let fd = openSecure(d.sroot, path, O_RDONLY)
    let st = fstatFd(fd)
    if st.st_size == 0:
      discard posix.close(fd)
      when defined(features.flysystem.useStdStreams):
        result = newStringStream("")
      else:
        result = default(MemFile)
        when not defined(windows):
          result.handle = -1
    else:
      when defined(features.flysystem.useStdStreams):
        result = newStringStream(readAllFd(fd))
        discard posix.close(fd)
      else:
        result = MemFile(mem: mmapFd(fd, st.st_size.int),
          size: st.st_size.int, handle: -1)
        discard posix.close(fd)

method writeStream*(d: LocalDriver, path: string, src: File) =
  ## Streams the contents of an open file handle `src` to the specified path.
  ## Parent directories are created if needed. The write is atomic.
  sandboxPassthrough("write stream", path):
    ensureParentSecure(d.sroot, path)
    let (dirFd, base) = openSecureParent(d.sroot, path)
    defer: discard posix.close(dirFd)
    let (tmpFd, tmp) = openTempIn(dirFd, base)
    try:
      var buf: array[8192, byte]
      while true:
        let n = src.readBuffer(addr buf[0], buf.len)
        if n <= 0: break
        writeBufFd(tmpFd, buf, n)
      if posix.fchmod(tmpFd, Mode(0o600)) != 0:
        raise newException(StorageError, "Failed to set permissions")
    finally:
      discard posix.close(tmpFd)
    commitTemp(dirFd, tmp, base)

method append*(d: LocalDriver, path, content: string) =
  ## Appends `content` to the file at the specified path. Creates the file
  ## (and parent directories) if it does not exist yet.
  sandboxPassthrough("append to", path):
    ensureParentSecure(d.sroot, path)
    let fd = openSecure(d.sroot, path,
      O_WRONLY or O_CREAT or O_APPEND, Mode(0o666))
    defer: discard posix.close(fd)
    writeAllFd(fd, content)

method appendStream*(d: LocalDriver, path: string, src: File) =
  ## Appends the contents of an open file handle `src` to the file at the
  ## specified path. Creates the file (and parent directories) if it does
  ## not exist yet.
  sandboxPassthrough("append stream to", path):
    ensureParentSecure(d.sroot, path)
    let fd = openSecure(d.sroot, path,
      O_WRONLY or O_CREAT or O_APPEND, Mode(0o666))
    defer: discard posix.close(fd)
    var buf: array[8192, byte]
    while true:
      let n = src.readBuffer(addr buf[0], buf.len)
      if n <= 0: break
      writeBufFd(fd, buf, n)

method delete*(d: LocalDriver, path: string) =
  ## Deletes a file from the local filesystem at the specified path.
  ## Missing paths are a silent no-op.
  ##
  ## The path is resolved against the driver's root directory.
  sandboxPassthrough("delete", path):
    removeSecure(d.sroot, path)

method exists*(d: LocalDriver, path: string): bool =
  ## Checks if a file or directory exists at the specified path on the
  ## local filesystem. Uses `lstat` semantics: a dangling symlink itself
  ## counts as present; use `read` to confirm it resolves.
  sandboxPassthrough("check existence of", path):
    lstatSecure(d.sroot, path).present

method list*(d: LocalDriver, path: string,
    recursive = false): seq[FileMetadata] =
  ## Lists files and directories at the specified path. If `recursive` is true,
  ## it will list all files and directories recursively, including empty
  ## directories. Returns a sequence of FileMetadata objects.
  sandboxPassthrough("list", path):
    for (rel, st) in listSecure(d.sroot, path, recursive):
      result.add(statMeta(rel, st))

method move*(d: LocalDriver, src, dest: string) =
  ## Moves a file from `src` to `dest` on the local filesystem.
  ##
  ## Creates parent directories if needed. A symlink is moved as a link —
  ## `renameat` never follows — so no content crosses the boundary.
  sandboxPassthrough("move '" & src & "' to '" & dest & "'", src):
    renameSecure(d.sroot, src, dest)

method copy*(d: LocalDriver, src, dest: string) =
  ## Copies a file from `src` to `dest` on the local filesystem.
  ##
  ## Creates parent directories if needed. A symlinked source resolves
  ## transparently when contained; an outside-pointing one fails closed.
  sandboxPassthrough("copy '" & src & "' to '" & dest & "'", src):
    copyFileSecure(d.sroot, src, dest)

method makeDir*(d: LocalDriver, path: string) =
  ## Creates a directory at the specified path. Creates parent
  ## directories if needed.
  sandboxPassthrough("create directory", path):
    ensureDirsSecure(d.sroot, path)

method deleteDir*(d: LocalDriver, path: string, force = false) =
  ## Deletes a directory at the specified path. If `force` is false, only an
  ## empty directory can be deleted; otherwise a `StorageError` is raised.
  ## If `force` is true, the directory is deleted recursively.
  sandboxPassthrough("delete directory", path):
    if force:
      removeTreeSecure(d.sroot, path)
    else:
      let (present, st) = lstatSecure(d.sroot, path)
      if not present or not S_ISDIR(st.st_mode):
        return
      if listSecure(d.sroot, path, false).len > 0:
        raise newException(StorageError, "Directory not empty: " & path)
      removeSecure(d.sroot, path)

method setVisibility*(d: LocalDriver, path: string, visibility: Visibility) =
  ## Sets the file visibility. `visPublic` maps to world-readable permissions
  ## (0o644), `visPrivate` to user-only (0o600).
  sandboxPassthrough("set visibility of", path):
    let fd = openSecure(d.sroot, path, O_RDONLY)
    defer: discard posix.close(fd)
    let perms = if visibility == visPublic: Mode(0o644) else: Mode(0o600)
    if posix.fchmod(fd, perms) != 0:
      raise newException(StorageError, "Failed to set visibility")

method visibility*(d: LocalDriver, path: string): Visibility =
  ## Returns the visibility of the file at the specified path, based on
  ## its actual filesystem permissions.
  sandboxPassthrough("get visibility of", path):
    let fd = openSecure(d.sroot, path, O_RDONLY)
    defer: discard posix.close(fd)
    let st = fstatFd(fd)
    if (st.st_mode.int32 and sjS_IROTH) != 0: visPublic else: visPrivate

method metadata*(d: LocalDriver, path: string): FileMetadata =
  ## Retrieves metadata for a file or directory at the specified path,
  ## including size, last modified time, and whether it's a directory.
  sandboxPassthrough("retrieve metadata of", path):
    let fd = openSecure(d.sroot, path, O_RDONLY)
    defer: discard posix.close(fd)
    statMeta(normalizeRel(d.sroot, path), fstatFd(fd))

method size*(d: LocalDriver, path: string): int64 =
  ## Returns the size in bytes — reuses `metadata` internally.
  d.metadata(path).size

method lastModified*(d: LocalDriver, path: string): times.Time =
  ## Returns the last modification time — reuses `metadata` internally.
  d.metadata(path).lastModified

method checksum*(d: LocalDriver, path: string): string =
  ## Returns the MD5 checksum of the file at the specified path.
  getMD5(d.read(path))

method mimeType*(d: LocalDriver, path: string): string =
  ## Returns the MIME type of the file at the specified path, inferred from
  ## its file extension via the `mimedb` database.
  let ext = splitFile(path).ext
  if ext.len == 0:
    return "application/octet-stream"
  getMimeType(ext[1..^1]).get("application/octet-stream")

method touch*(d: LocalDriver, path: string) =
  ## Creates an empty file at `path` if it does not exist, or updates its
  ## last-modified time.
  sandboxPassthrough("touch", path):
    touchSecure(d.sroot, path)

iterator readLines*(d: LocalDriver, path: string): string =
  ## Iterates over the lines of the file at `path`.
  ## Default backend uses a memory-mapped read; with
  ## `-d:features.flysystem.useStdStreams` it uses a `StringStream`.
  ## A single internal buffer is reused across lines, so no per-line allocations
  ## happen. The yielded string is only valid until the next iteration — copy it
  ## if you need to keep it.
  sandboxPassthrough("read", path):
    let fd = openSecure(d.sroot, path, O_RDONLY)
    let st = fstatFd(fd)
    if st.st_size == 0:
      discard posix.close(fd)
    else:
      when defined(features.flysystem.useStdStreams):
        let content = readAllFd(fd)
        discard posix.close(fd)
        var s = newStringStream(content)
        var buf = newString(0)
        while s.readLine(buf):
          yield buf
        s.close()
      else:
        let mem = mmapFd(fd, st.st_size.int)
        discard posix.close(fd)
        var mf = MemFile(mem: mem, size: st.st_size.int, handle: -1)
        var buf = newString(0)
        for line in lines(mf, buf):
          yield line
        close(mf)

method copyDir*(d: LocalDriver, src, dest: string) =
  ## Recursively copies a directory from `src` to `dest`, including empty
  ## directories. Creates parent directories if needed.
  sandboxPassthrough("copy directory '" & src & "' to '" & dest & "'", src):
    copyDirSecure(d.sroot, src, dest)

method moveDir*(d: LocalDriver, src, dest: string) =
  ## Moves a directory from `src` to `dest`. Creates parent directories if
  ## needed.
  sandboxPassthrough("move directory '" & src & "' to '" & dest & "'", src):
    renameSecure(d.sroot, src, dest)

method createSymlink*(d: LocalDriver, path, target: string) {.base.} =
  ## Creates a symbolic link at `path` pointing to `target`. `target` must
  ## name something inside the driver root; anything else is refused at
  ## creation, and any link that would resolve outside is unusable afterwards.
  sandboxPassthrough("create symlink '" & path & "' -> '" & target & "'",
      path):
    checkLexicalContained(d.sroot, target)
    let (dirFd, base) = openSecureParent(d.sroot, path)
    defer: discard posix.close(dirFd)
    symlinkIn(dirFd, target, base)

method isSymlink*(d: LocalDriver, path: string): bool {.base.} =
  ## Returns true if the file at `path` is a symbolic link.
  sandboxPassthrough("check symlink", path):
    let (present, st) = lstatSecure(d.sroot, path)
    present and S_ISLNK(st.st_mode)

method readLink*(d: LocalDriver, path: string): string {.base.} =
  ## Returns the target of the symbolic link at `path`, relative to the root
  ## when it names something inside it, raw otherwise.
  sandboxPassthrough("read symlink", path):
    let (dirFd, base) = openSecureParent(d.sroot, path)
    defer: discard posix.close(dirFd)
    let target = readlinkIn(dirFd, base)
    if target.isAbsolute and
        (target == d.sroot.path or
         target.startsWith(d.sroot.path & DirSep)):
      return target[d.sroot.path.len + 1 .. ^1]
    target

template withLock*(d: LocalDriver, path: string, body: untyped) =
  ## Executes `body` while holding an exclusive advisory lock on the file at
  ## `path`. The file is created if it does not exist. POSIX-only.
  sandboxPassthrough("acquire lock on", path):
    ensureParentSecure(d.sroot, path)
    let lockFd = openSecure(d.sroot, path,
      O_RDWR or O_CREAT, Mode(0o600))
    try:
      when defined(posix):
        var fl: Tflock
        fl.l_type = F_WRLCK.cshort
        fl.l_whence = SEEK_SET.cshort
        fl.l_start = 0
        fl.l_len = 0
        if fcntl(lockFd, F_SETLKW, addr fl) != 0:
          raise newException(StorageError,
            "Failed to acquire lock on '" & path & "'")
      try:
        body
      finally:
        when defined(posix):
          var ul: Tflock
          ul.l_type = F_UNLCK.cshort
          ul.l_whence = SEEK_SET.cshort
          discard fcntl(lockFd, F_SETLK, addr ul)
    finally:
      discard posix.close(lockFd)

method search*(d: LocalDriver, pattern: string): seq[string] =
  ## Returns paths (relative to the root) matching the glob `pattern`,
  ## e.g. `"*.txt"` or `"sub/*.log"`.
  sandboxPassthrough("search", pattern):
    searchSecure(d.sroot, pattern)

method copyFromHost*(d: LocalDriver, srcAbs, destRel: string) {.base.} =
  ## Copy a file or directory from an absolute host path `srcAbs`
  ## (outside the driver root, e.g. a project readonly disk) into
  ## the driver at `destRel`. Used for `clue install` (local) which
  ## copies from the project disk to the clue disk.
  ##
  ## The source is an explicit, caller-chosen absolute path — intentionally
  ## outside containment, by API contract. Only the destination is contained.
  sandboxPassthrough("copyFromHost '" & srcAbs & "' -> '" & destRel & "'",
      destRel):
    let src = srcAbs.expandTilde.absolutePath
    if dirExists(src):
      ensureDirsSecure(d.sroot, destRel)
      for entry in walkDir(src):
        let target = destRel / extractFilename(entry.path)
        case entry.kind
        of pcDir:
          copyDir(entry.path, target)
        of pcFile:
          copyFile(entry.path, target)
        else: discard
    elif fileExists(src):
      ensureParentSecure(d.sroot, destRel)
      let (dirFd, base) = openSecureParent(d.sroot, destRel)
      defer: discard posix.close(dirFd)
      let srcFd = posix.open(src.cstring, O_RDONLY)
      if srcFd < 0:
        raise newException(StorageError, "Source not found: " & srcAbs)
      defer: discard posix.close(srcFd)
      let dstFd = createFileIn(dirFd, base)
      defer: discard posix.close(dstFd)
      var buf: array[8192, byte]
      while true:
        let n = posix.read(srcFd, addr buf[0], buf.len)
        if n <= 0: break
        writeBufFd(dstFd, buf, n)
    else:
      raise newException(StorageError, "Source not found: " & srcAbs)

method importFrom*(d: LocalDriver, srcDriver: StorageDriver,
                   srcRel, destRel: string) {.base.} =
  ## Copy between two drivers (e.g. project readonly disk -> clue disk).
  ## `srcRel` is relative to `srcDriver.root`, `destRel` to `d.root`.
  ##
  ## When the source is a `LocalDriver`, both sides stay inside their
  ## respective roots. Any other driver type (or an absolute `srcRel`) reads
  ## the source by path — the explicit cross-boundary case, by API contract.
  sandboxPassthrough("importFrom '" & srcRel & "' -> '" & destRel & "'",
      destRel):
    if srcDriver of LocalDriver:
      let src = LocalDriver(srcDriver)
      let srcFd = openSecure(src.sroot, srcRel, O_RDONLY)
      defer: discard posix.close(srcFd)
      ensureParentSecure(d.sroot, destRel)
      let (dirFd, base) = openSecureParent(d.sroot, destRel)
      defer: discard posix.close(dirFd)
      let dstFd = createFileIn(dirFd, base)
      defer: discard posix.close(dstFd)
      var buf: array[8192, byte]
      while true:
        let n = posix.read(srcFd, addr buf[0], buf.len)
        if n <= 0: break
        writeBufFd(dstFd, buf, n)
    else:
      let srcFull =
        if srcRel.isAbsolute: srcRel
        else: srcDriver.root / srcRel
      if dirExists(srcFull):
        ensureDirsSecure(d.sroot, destRel)
        for entry in walkDir(srcFull):
          let target = destRel / extractFilename(entry.path)
          case entry.kind
          of pcDir:
            copyDir(entry.path, target)
          of pcFile:
            copyFile(entry.path, target)
          else: discard
      elif fileExists(srcFull):
        ensureParentSecure(d.sroot, destRel)
        let (dirFd, base) = openSecureParent(d.sroot, destRel)
        defer: discard posix.close(dirFd)
        let srcFd = posix.open(srcFull.cstring, O_RDONLY)
        if srcFd < 0:
          raise newException(StorageError, "Source not found: " & srcRel)
        defer: discard posix.close(srcFd)
        let dstFd = createFileIn(dirFd, base)
        defer: discard posix.close(dstFd)
        var buf: array[8192, byte]
        while true:
          let n = posix.read(srcFd, addr buf[0], buf.len)
          if n <= 0: break
          writeBufFd(dstFd, buf, n)
      else:
        raise newException(StorageError, "Source not found: " & srcRel)

method diskUsage*(d: LocalDriver): tuple[total, free, used: int64] {.base.} =
  ## Returns the total, free and used bytes on the filesystem containing the
  ## driver root. POSIX-only.
  when defined(posix):
    var vfs: Statvfs
    if statvfs(d.root.cstring, vfs) != 0:
      raise newException(StorageError, "Failed to query disk usage for '" & d.root & "'")
    let bsize = vfs.f_frsize.int64
    result.total = vfs.f_blocks.int64 * bsize
    result.free = vfs.f_bavail.int64 * bsize
    result.used = (vfs.f_blocks.int64 - vfs.f_bfree.int64) * bsize
  else:
    raise newException(StorageError, "diskUsage is only supported on POSIX")

method chmod*(d: LocalDriver, path: string, mode: int) {.base.} =
  ## Sets the file permission bits of `path` to `mode` (e.g. 0o644).
  ## POSIX-only.
  sandboxPassthrough("chmod", path):
    when defined(posix):
      let fd = openSecure(d.sroot, path, O_RDONLY)
      defer: discard posix.close(fd)
      if posix.fchmod(fd, Mode(mode)) != 0:
        raise newException(StorageError, "Failed to chmod '" & path & "'")
    else:
      raise newException(StorageError, "chmod is only supported on POSIX")

method chown*(d: LocalDriver, path: string, uid, gid: int) {.base.} =
  ## Changes the owner and group of the file at `path`. POSIX-only.
  sandboxPassthrough("chown", path):
    when defined(posix):
      let fd = openSecure(d.sroot, path, O_RDONLY)
      defer: discard posix.close(fd)
      if posix.fchown(fd, Uid(uid), Gid(gid)) != 0:
        raise newException(StorageError, "Failed to chown '" & path & "'")
    else:
      raise newException(StorageError, "chown is only supported on POSIX")
