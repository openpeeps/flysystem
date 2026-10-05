#
# Async Local Driver — non-blocking counterpart to LocalDriver
# Uses std/asyncdispatch (stdlib only, no chronos). Path resolution goes
# through the same verified descriptor walk as the sync driver
# (`securejoin`), so containment is identical; the walk and fd IO run
# synchronously inside the async methods (an `openat` chain on a local
# filesystem does not block in practice). For true non-blocking directory IO,
# replace with a threadpool if needed.

import std/[os, strutils, options, times, asyncdispatch, syncio, posix]
import pkg/mimedb
import checksums/md5
import ./core
import ./securejoin

type
  AsyncLocalDriver* = ref object of StorageDriver
    ## Async filesystem driver using an absolute runtime root
    ## (inherited from `StorageDriver`), like `LocalDriver`.
    ## Implements the same methods asynchronously — `await d.write(...)`.
    ## Note: the inherited sync `StorageDriver` methods raise
    ## `StorageError("Not implemented")`.
    sroot*: SecureRoot
    ## The root held open as a directory descriptor plus its canonical path.

proc newAsyncLocalDriver*(root: string): AsyncLocalDriver =
  ## Creates an AsyncLocalDriver. `root` is an absolute runtime path.
  ## Example: pass in the value of an env var or config key at startup.
  let sroot = openSecureRoot(root)
  result = AsyncLocalDriver(root: sroot.path, sroot: sroot)

proc closeDriver*(d: AsyncLocalDriver) =
  ## Releases the held root descriptor. Optional; drivers typically live for
  ## process lifetime.
  closeSecureRoot(d.sroot)

#
# file content — resolved through the verified walk, fd IO
#

method write*(d: AsyncLocalDriver, path, content: string,
    visibility = visPrivate): Future[void] {.base, async.} =
  ## Asynchronously writes `content` to the file at `path`. The write is
  ## atomic: content is first written to a temporary file in the same
  ## directory and then renamed over the target, so a crash mid-write
  ## never corrupts the file.
  sandboxPassthrough("write", path):
    atomicWriteSecure(d.sroot, path, content,
      if visibility == visPublic: Mode(0o644) else: Mode(0o600))

method read*(d: AsyncLocalDriver, path: string): Future[string] {.base, async.} =
  ## Asynchronously reads a file from the local filesystem at the specified path.
  ##
  ## The path is resolved against the driver's root directory.
  sandboxPassthrough("read", path):
    let fd = openSecure(d.sroot, path, O_RDONLY)
    defer: discard posix.close(fd)
    readAllFd(fd)

method append*(d: AsyncLocalDriver, path, content: string): Future[void] {.base, async.} =
  ## Asynchronously appends `content` to the file at the specified path.
  ## Creates the file (and parent directories) if it does not exist yet.
  sandboxPassthrough("append to", path):
    ensureParentSecure(d.sroot, path)
    let fd = openSecure(d.sroot, path,
      O_WRONLY or O_CREAT or O_APPEND, Mode(0o666))
    defer: discard posix.close(fd)
    writeAllFd(fd, content)

method writeStream*(d: AsyncLocalDriver, path: string, src: File): Future[void] {.base, async.} =
  ## Streams the contents of an open file handle `src` to the specified path.
  ## Parent directories are created if needed. The write is atomic. Note:
  ## chunk reads from the caller-provided `src` handle are synchronous.
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

method appendStream*(d: AsyncLocalDriver, path: string, src: File): Future[void] {.base, async.} =
  ## Appends the contents of an open file handle `src` to the file at the
  ## specified path. Creates the file (and parent directories) if it does
  ## not exist yet. Note: chunk reads from the caller-provided `src` handle
  ## are synchronous.
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

method readStream*(d: AsyncLocalDriver, path: string): Future[string] {.base, async.} =
  ## Asynchronously reads the whole file and returns its content.
  ## For memmap-style access, use the sync LocalDriver.readStream.
  return await d.read(path)

#
# metadata / filesystem — wrapped sync (blocking) but inside async proc
#
method metadata*(d: AsyncLocalDriver, path: string): Future[FileMetadata] {.base, async.} =
  ## Retrieves metadata for a file or directory at the specified path,
  ## including size, last modified time, and whether it's a directory.
  sandboxPassthrough("retrieve metadata of", path):
    let fd = openSecure(d.sroot, path, O_RDONLY)
    defer: discard posix.close(fd)
    statMeta(normalizeRel(d.sroot, path), fstatFd(fd))

method size*(d: AsyncLocalDriver, path: string): Future[int64] {.base, async.} =
  ## Returns the size in bytes — reuses `metadata` internally.
  let m = await d.metadata(path)
  return m.size

method lastModified*(d: AsyncLocalDriver, path: string): Future[times.Time] {.base, async.} =
  ## Returns the last modification time — reuses `metadata` internally.
  let m = await d.metadata(path)
  return m.lastModified

method checksum*(d: AsyncLocalDriver, path: string): Future[string] {.base, async.} =
  ## Returns the MD5 checksum of the file at the specified path.
  let content = await d.read(path)
  return getMD5(content)

method mimeType*(d: AsyncLocalDriver, path: string): Future[string] {.base, async.} =
  ## Returns the MIME type of the file at the specified path, inferred from
  ## its file extension via the `mimedb` database.
  let ext = splitFile(path).ext
  if ext.len == 0:
    return "application/octet-stream"
  return getMimeType(ext[1..^1]).get("application/octet-stream")

method exists*(d: AsyncLocalDriver, path: string): Future[bool] {.base, async.} =
  ## Checks if a file or directory exists at the specified path on the
  ## local filesystem.
  sandboxPassthrough("check existence of", path):
    lstatSecure(d.sroot, path).present

method delete*(d: AsyncLocalDriver, path: string): Future[void] {.base, async.} =
  ## Deletes a file from the local filesystem at the specified path.
  ## Missing paths are a silent no-op.
  ##
  ## The path is resolved against the driver's root directory.
  sandboxPassthrough("delete", path):
    removeSecure(d.sroot, path)

method makeDir*(d: AsyncLocalDriver, path: string): Future[void] {.base, async.} =
  ## Creates a directory at the specified path. Creates parent
  ## directories if needed.
  sandboxPassthrough("create directory", path):
    ensureDirsSecure(d.sroot, path)

method deleteDir*(d: AsyncLocalDriver, path: string, force = false): Future[void] {.base, async.} =
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

method touch*(d: AsyncLocalDriver, path: string): Future[void] {.base, async.} =
  ## Creates an empty file at `path` if it does not exist, or updates its
  ## last-modified time. Never truncates an existing file.
  sandboxPassthrough("touch", path):
    touchSecure(d.sroot, path)

method setVisibility*(d: AsyncLocalDriver, path: string, visibility: Visibility): Future[void] {.base, async.} =
  ## Sets the file visibility. `visPublic` maps to world-readable permissions
  ## (0o644), `visPrivate` to user-only (0o600).
  sandboxPassthrough("set visibility of", path):
    let fd = openSecure(d.sroot, path, O_RDONLY)
    defer: discard posix.close(fd)
    let perms = if visibility == visPublic: Mode(0o644) else: Mode(0o600)
    if posix.fchmod(fd, perms) != 0:
      raise newException(StorageError, "Failed to set visibility")

method visibility*(d: AsyncLocalDriver, path: string): Future[Visibility] {.base, async.} =
  ## Returns the visibility of the file at the specified path, based on
  ## its actual filesystem permissions.
  sandboxPassthrough("get visibility of", path):
    let fd = openSecure(d.sroot, path, O_RDONLY)
    defer: discard posix.close(fd)
    let st = fstatFd(fd)
    if (st.st_mode.int32 and sjS_IROTH) != 0: visPublic else: visPrivate

method list*(d: AsyncLocalDriver, path: string, recursive = false): Future[seq[FileMetadata]] {.base, async.} =
  ## Lists files and directories at the specified path. If `recursive` is true,
  ## it will list all files and directories recursively, including empty
  ## directories. Returns a sequence of FileMetadata objects.
  sandboxPassthrough("list", path):
    for (rel, st) in listSecure(d.sroot, path, recursive):
      result.add(statMeta(rel, st))

method move*(d: AsyncLocalDriver, src, dest: string): Future[void] {.base, async.} =
  ## Moves a file from `src` to `dest` on the local filesystem.
  ##
  ## Creates parent directories if needed.
  sandboxPassthrough("move '" & src & "' to '" & dest & "'", src):
    renameSecure(d.sroot, src, dest)

method copy*(d: AsyncLocalDriver, src, dest: string): Future[void] {.base, async.} =
  ## Copies a file from `src` to `dest` on the local filesystem.
  ##
  ## Creates parent directories if needed.
  sandboxPassthrough("copy '" & src & "' to '" & dest & "'", src):
    copyFileSecure(d.sroot, src, dest)

method copyDir*(d: AsyncLocalDriver, src, dest: string): Future[void] {.base, async.} =
  ## Recursively copies a directory from `src` to `dest`, including empty
  ## directories. Creates parent directories if needed.
  sandboxPassthrough("copy directory '" & src & "' to '" & dest & "'", src):
    copyDirSecure(d.sroot, src, dest)

method moveDir*(d: AsyncLocalDriver, src, dest: string): Future[void] {.base, async.} =
  ## Moves a directory from `src` to `dest`. Creates parent directories if
  ## needed.
  sandboxPassthrough("move directory '" & src & "' to '" & dest & "'", src):
    renameSecure(d.sroot, src, dest)

method search*(d: AsyncLocalDriver, pattern: string): Future[seq[string]] {.base, async.} =
  ## Returns paths (relative to the root) matching the glob `pattern`,
  ## e.g. `"*.txt"` or `"sub/*.log"`.
  sandboxPassthrough("search", pattern):
    searchSecure(d.sroot, pattern)

method createSymlink*(d: AsyncLocalDriver, path, target: string): Future[void] {.base, async.} =
  ## Creates a symbolic link at `path` pointing to `target`. `target` must
  ## name something inside the driver root.
  sandboxPassthrough("create symlink '" & path & "' -> '" & target & "'",
      path):
    checkLexicalContained(d.sroot, target)
    let (dirFd, base) = openSecureParent(d.sroot, path)
    defer: discard posix.close(dirFd)
    symlinkIn(dirFd, target, base)

method isSymlink*(d: AsyncLocalDriver, path: string): Future[bool] {.base, async.} =
  ## Returns true if the file at `path` is a symbolic link.
  sandboxPassthrough("check symlink", path):
    let (present, st) = lstatSecure(d.sroot, path)
    present and S_ISLNK(st.st_mode)

method readLink*(d: AsyncLocalDriver, path: string): Future[string] {.base, async.} =
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

method diskUsage*(d: AsyncLocalDriver): Future[tuple[total, free, used: int64]] {.base, async.} =
  ## Returns the total, free and used bytes on the filesystem containing the
  ## driver root. POSIX-only.
  when defined(posix):
    var vfs: Statvfs
    if statvfs(d.root.cstring, vfs) != 0:
      raise newException(StorageError, "Failed to query disk usage for '" & d.root & "'")
    let bsize = vfs.f_frsize.int64
    return (vfs.f_blocks.int64 * bsize, vfs.f_bavail.int64 * bsize,
            (vfs.f_blocks.int64 - vfs.f_bfree.int64) * bsize)
  else:
    raise newException(StorageError, "diskUsage is only supported on POSIX")

method chmod*(d: AsyncLocalDriver, path: string, mode: int): Future[void] {.base, async.} =
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

method chown*(d: AsyncLocalDriver, path: string, uid, gid: int): Future[void] {.base, async.} =
  ## Changes the owner and group of the file at `path`. POSIX-only.
  sandboxPassthrough("chown", path):
    when defined(posix):
      let fd = openSecure(d.sroot, path, O_RDONLY)
      defer: discard posix.close(fd)
      if posix.fchown(fd, Uid(uid), Gid(gid)) != 0:
        raise newException(StorageError, "Failed to chown '" & path & "'")
    else:
      raise newException(StorageError, "chown is only supported on POSIX")

method readLines*(d: AsyncLocalDriver, path: string): Future[seq[string]] {.base, async.} =
  ## Returns all lines of the file at `path`, read asynchronously.
  ## Behaves like the sync `readLines` iterator (handles `\n` and `\r\n`,
  ## no trailing empty line) but returns a sequence instead of yielding.
  let content = await d.read(path)
  if content.len == 0: return @[]
  # splitLines handles \n and \r\n; we mimic iterator behaviour (no trailing empty)
  var lines = content.splitLines()
  # splitLines on "a\n" yields @["a",""]; trim trailing empty caused by final newline
  if lines.len > 0 and lines[^1] == "" and content[^1] == '\n':
    lines.setLen(lines.len - 1)
  return lines
