#
# Async Local Driver — non-blocking counterpart to LocalDriver
# Uses std/asyncfile + std/asyncdispatch (stdlib only, no chronos).
# File content goes through true non-blocking IO; directory / metadata /
# POSIX ops run synchronously inside the async methods.
# For true non-blocking directory IO, replace with a threadpool if needed.

import std/[os, strutils, options, times, asyncdispatch, asyncfile, syncio, posix]
import pkg/mimedb
import checksums/md5
import ./core

type
  AsyncLocalDriver* = ref object of StorageDriver
    ## Async filesystem driver using an absolute runtime root
    ## (inherited from `StorageDriver`), like `LocalDriver`.
    ## Implements the same methods asynchronously — `await d.write(...)`.
    ## Note: the inherited sync `StorageDriver` methods raise
    ## `StorageError("Not implemented")`.

# 
# helpers (duplicated from local.nim to avoid circular import / visibility)
# 
proc resolvePath(d: AsyncLocalDriver, path: string): string =
  ## Resolves a relative path against the runtime root. Absolute paths are
  ## normalized as-is, as long as they stay inside the root.
  ##
  ## Prevents path traversal outside the root for security
  let resolved = normalizedPath(if isAbsolute(path): path else: d.root / path)
  if not resolved.startsWith(d.root):
    raise newException(StorageError, "Path traversal detected: " & path)
  resolved

var tmpCounter {.threadvar.}: int64

proc tempPath(full: string): string =
  ## Returns a unique temporary path in the same directory as `full`,
  ## suitable for atomic writes.
  inc tmpCounter
  full & ".tmp" & $getCurrentProcessId() & "." & $tmpCounter

proc newAsyncLocalDriver*(root: string): AsyncLocalDriver =
  ## Creates an AsyncLocalDriver. `root` is an absolute runtime path.
  ## Example: pass in the value of an env var or config key at startup.
  result = AsyncLocalDriver(root: expandTilde(root).absolutePath)
  if not dirExists(result.root):
    createDir(result.root)

# 
# file content — true async via asyncfile
# 
method write*(d: AsyncLocalDriver, path, content: string,
    visibility = visPrivate): Future[void] {.base, async.} =
  ## Asynchronously writes `content` to the file at `path`. The write is
  ## atomic: content is first written to a temporary file in the same
  ## directory and then renamed over the target, so a crash mid-write
  ## never corrupts the file.
  let full = d.resolvePath(path)
  try:
    createDir(full.parentDir)
    let tmp = tempPath(full)
    let f = openAsync(tmp, fmWrite)
    await f.write(content)
    f.close()
    # set visibility on tmp before rename (reuse LocalDriver perms logic)
    let perms =
      if visibility == visPublic:
        {fpUserRead, fpUserWrite, fpGroupRead, fpOthersRead}
      else:
        {fpUserRead, fpUserWrite}
    setFilePermissions(tmp, perms)
    moveFile(tmp, full)
  except CatchableError as e:
    # openAsync/write may raise StorageError from resolvePath — preserve
    if e of StorageError: raise e
    raise newException(StorageError, "Failed to write '" & path & "': " & e.msg)

method read*(d: AsyncLocalDriver, path: string): Future[string] {.base, async.} =
  ## Asynchronously reads a file from the local filesystem at the specified path.
  ##
  ## The path is resolved against the driver's root directory.
  let full = d.resolvePath(path)
  try:
    let f = openAsync(full, fmRead)
    result = await f.readAll()
    f.close()
  except CatchableError as e:
    if e of StorageError: raise e
    raise newException(StorageError, "Failed to read '" & path & "': " & e.msg)

method append*(d: AsyncLocalDriver, path, content: string): Future[void] {.base, async.} =
  ## Asynchronously appends `content` to the file at the specified path.
  ## Creates the file (and parent directories) if it does not exist yet.
  let full = d.resolvePath(path)
  try:
    createDir(full.parentDir)
    # O_APPEND: creates the file if missing, never truncates —
    # asyncfile uses plain write(), so appends are truly async
    let f = openAsync(full, fmAppend)
    await f.write(content)
    f.close()
  except CatchableError as e:
    if e of StorageError: raise e
    raise newException(StorageError, "Failed to append to '" & path & "': " & e.msg)

method writeStream*(d: AsyncLocalDriver, path: string, src: File): Future[void] {.base, async.} =
  ## Streams the contents of an open file handle `src` to the specified path
  ## without blocking the event loop. Parent directories are created if needed.
  ## The write is atomic. Note: chunk reads from the caller-provided `src`
  ## handle are synchronous; destination writes are awaited.
  let full = d.resolvePath(path)
  try:
    createDir(full.parentDir)
    let tmp = tempPath(full)
    let dst = openAsync(tmp, fmWrite)
    var buf: array[8192, byte]
    while true:
      # src is a caller-provided sync handle, so chunk reads block;
      # destination writes are awaited
      let n = src.readBuffer(addr buf[0], buf.len)
      if n <= 0: break
      await dst.writeBuffer(addr buf[0], n)
    dst.close()
    setFilePermissions(tmp, {fpUserRead, fpUserWrite})
    moveFile(tmp, full)
  except CatchableError as e:
    if e of StorageError: raise e
    raise newException(StorageError, "Failed to write stream '" & path & "': " & e.msg)

method appendStream*(d: AsyncLocalDriver, path: string, src: File): Future[void] {.base, async.} =
  ## Appends the contents of an open file handle `src` to the file at the
  ## specified path without blocking the event loop. Creates the file (and
  ## parent directories) if it does not exist yet. Note: chunk reads from the
  ## caller-provided `src` handle are synchronous; destination writes are awaited.
  let full = d.resolvePath(path)
  try:
    createDir(full.parentDir)
    let dst = openAsync(full, fmAppend)
    var buf: array[8192, byte]
    while true:
      # src is a caller-provided sync handle, so chunk reads block;
      # destination writes are awaited
      let n = src.readBuffer(addr buf[0], buf.len)
      if n <= 0: break
      await dst.writeBuffer(addr buf[0], n)
    dst.close()
  except CatchableError as e:
    if e of StorageError: raise e
    raise newException(StorageError, "Failed to append stream to '" & path & "': " & e.msg)

method readStream*(d: AsyncLocalDriver, path: string): Future[string] {.base, async.} =
  ## Asynchronously reads the whole file via asyncfile and returns its content.
  ## For memmap-style access, use the sync LocalDriver.readStream.
  return await d.read(path)

# 
# metadata / filesystem — wrapped sync (blocking) but inside async proc
# 
method metadata*(d: AsyncLocalDriver, path: string): Future[FileMetadata] {.base, async.} =
  ## Retrieves metadata for a file or directory at the specified path,
  ## including size, last modified time, and whether it's a directory.
  let full = d.resolvePath(path)
  try:
    result = FileMetadata(
      path: full.relativePath(d.root),
      size: getFileSize(full),
      lastModified: getLastModificationTime(full),
      isDir: dirExists(full)
    )
  except CatchableError as e:
    if e of StorageError: raise e
    raise newException(StorageError, "Failed to retrieve metadata of '" & path & "': " & e.msg)

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
  let full = d.resolvePath(path)
  try:
    return fileExists(full) or dirExists(full)
  except CatchableError as e:
    raise newException(StorageError, "Failed to check existence of '" & path & "': " & e.msg)

method delete*(d: AsyncLocalDriver, path: string): Future[void] {.base, async.} =
  ## Deletes a file from the local filesystem at the specified path.
  ##
  ## The path is resolved against the driver's root directory.
  let full = d.resolvePath(path)
  try:
    removeFile(full)
  except OSError:
    try: removeDir(full)
    except CatchableError as e:
      raise newException(StorageError, "Failed to delete '" & path & "': " & e.msg)
  except CatchableError as e:
    raise newException(StorageError, "Failed to delete '" & path & "': " & e.msg)

method makeDir*(d: AsyncLocalDriver, path: string): Future[void] {.base, async.} =
  ## Creates a directory at the specified path. Creates parent
  ## directories if needed.
  let full = d.resolvePath(path)
  try:
    createDir(full)
  except CatchableError as e:
    raise newException(StorageError, "Failed to create directory '" & path & "': " & e.msg)

method deleteDir*(d: AsyncLocalDriver, path: string, force = false): Future[void] {.base, async.} =
  ## Deletes a directory at the specified path. If `force` is false, only an
  ## empty directory can be deleted; otherwise a `StorageError` is raised.
  ## If `force` is true, the directory is deleted recursively.
  let full = d.resolvePath(path)
  try:
    if force:
      removeDir(full)
    else:
      if not dirExists(full): return
      for _ in walkDir(full):
        raise newException(StorageError, "Directory not empty: " & path)
      removeDir(full)
  except StorageError: raise
  except CatchableError as e:
    raise newException(StorageError, "Failed to delete directory '" & path & "': " & e.msg)

method touch*(d: AsyncLocalDriver, path: string): Future[void] {.base, async.} =
  ## Creates an empty file at `path` if it does not exist, or updates its
  ## last-modified time. Never truncates an existing file.
  let full = d.resolvePath(path)
  try:
    createDir(full.parentDir)
    # O_APPEND + O_CREAT without O_TRUNC: creates an empty file if missing,
    # leaves existing content untouched — without blocking
    let f = openAsync(full, fmAppend)
    f.close()
    # the mtime bump has no async equivalent; sync syscall
    setLastModificationTime(full, getTime())
  except CatchableError as e:
    raise newException(StorageError, "Failed to touch '" & path & "': " & e.msg)

method setVisibility*(d: AsyncLocalDriver, path: string, visibility: Visibility): Future[void] {.base, async.} =
  ## Sets the file visibility. `visPublic` maps to world-readable permissions
  ## (0o644), `visPrivate` to user-only (0o600).
  let full = d.resolvePath(path)
  let perms =
    if visibility == visPublic: {fpUserRead, fpUserWrite, fpGroupRead, fpOthersRead}
    else: {fpUserRead, fpUserWrite}
  try:
    setFilePermissions(full, perms)
  except CatchableError as e:
    raise newException(StorageError, "Failed to set visibility of '" & path & "': " & e.msg)

method visibility*(d: AsyncLocalDriver, path: string): Future[Visibility] {.base, async.} =
  ## Returns the visibility of the file at the specified path, based on
  ## its actual filesystem permissions.
  let full = d.resolvePath(path)
  try:
    return if fpOthersRead in getFilePermissions(full): visPublic else: visPrivate
  except CatchableError as e:
    raise newException(StorageError, "Failed to get visibility of '" & path & "': " & e.msg)

proc collectEntries(d: AsyncLocalDriver, full: string, res: var seq[FileMetadata]) =
  ## Recursively collects entries, including empty directories.
  for entry in walkDir(full):
    res.add FileMetadata(
      path: entry.path.relativePath(d.root),
      size: (if entry.kind == pcFile: getFileSize(entry.path) else: 0),
      lastModified: getLastModificationTime(entry.path),
      isDir: entry.kind in {pcDir, pcLinkToDir})
    if entry.kind in {pcDir, pcLinkToDir}:
      collectEntries(d, entry.path, res)

method list*(d: AsyncLocalDriver, path: string, recursive = false): Future[seq[FileMetadata]] {.base, async.} =
  ## Lists files and directories at the specified path. If `recursive` is true,
  ## it will list all files and directories recursively, including empty
  ## directories. Returns a sequence of FileMetadata objects.
  let full = d.resolvePath(path)
  try:
    if recursive:
      var res: seq[FileMetadata]
      collectEntries(d, full, res)
      return res
    else:
      var res: seq[FileMetadata]
      for entry in walkDir(full):
        res.add FileMetadata(path: entry.path.relativePath(d.root),
          size: (if entry.kind == pcFile: getFileSize(entry.path) else: 0),
          lastModified: getLastModificationTime(entry.path),
          isDir: entry.kind in {pcDir, pcLinkToDir})
      return res
  except CatchableError as e:
    if e of StorageError: raise e
    raise newException(StorageError, "Failed to list '" & path & "': " & e.msg)

method move*(d: AsyncLocalDriver, src, dest: string): Future[void] {.base, async.} =
  ## Moves a file from `src` to `dest` on the local filesystem.
  ##
  ## Creates parent directories if needed.
  let srcFull = d.resolvePath(src)
  let destFull = d.resolvePath(dest)
  try:
    createDir(destFull.parentDir)
    moveFile(srcFull, destFull)
  except CatchableError as e:
    raise newException(StorageError, "Failed to move '" & src & "' to '" & dest & "': " & e.msg)

method copy*(d: AsyncLocalDriver, src, dest: string): Future[void] {.base, async.} =
  ## Copies a file from `src` to `dest` on the local filesystem.
  ##
  ## Creates parent directories if needed.
  let srcFull = d.resolvePath(src)
  let destFull = d.resolvePath(dest)
  try:
    createDir(destFull.parentDir)
    copyFile(srcFull, destFull)
  except CatchableError as e:
    raise newException(StorageError, "Failed to copy '" & src & "' to '" & dest & "': " & e.msg)

method copyDir*(d: AsyncLocalDriver, src, dest: string): Future[void] {.base, async.} =
  ## Recursively copies a directory from `src` to `dest`, including empty
  ## directories. Creates parent directories if needed.
  let srcFull = d.resolvePath(src)
  let destFull = d.resolvePath(dest)
  try:
    createDir(destFull)
    for entry in walkDir(srcFull):
      let target = destFull / extractFilename(entry.path)
      case entry.kind
      of pcDir: await d.copyDir(entry.path.relativePath(d.root), target.relativePath(d.root))
      of pcFile: copyFile(entry.path, target)
      else: discard
  except CatchableError as e:
    if e of StorageError: raise e
    raise newException(StorageError, "Failed to copy directory '" & src & "' to '" & dest & "': " & e.msg)

method moveDir*(d: AsyncLocalDriver, src, dest: string): Future[void] {.base, async.} =
  ## Moves a directory from `src` to `dest`. Creates parent directories if
  ## needed.
  let srcFull = d.resolvePath(src)
  let destFull = d.resolvePath(dest)
  try:
    createDir(destFull.parentDir)
    moveDir(srcFull, destFull)
  except CatchableError as e:
    raise newException(StorageError, "Failed to move directory '" & src & "' to '" & dest & "': " & e.msg)

method search*(d: AsyncLocalDriver, pattern: string): Future[seq[string]] {.base, async.} =
  ## Returns paths (relative to the root) matching the glob `pattern`,
  ## e.g. `"*.txt"` or `"sub/*.log"`.
  let (dir, name) = splitPath(pattern)
  let base = if dir.len == 0: d.root else: d.resolvePath(dir)
  try:
    var res: seq[string]
    for p in walkPattern(base / name):
      res.add p.relativePath(d.root)
    return res
  except CatchableError as e:
    if e of StorageError: raise e
    raise newException(StorageError, "Failed to search '" & pattern & "': " & e.msg)

method createSymlink*(d: AsyncLocalDriver, path, target: string): Future[void] {.base, async.} =
  ## Creates a symbolic link at `path` pointing to `target`. `target` must
  ## resolve inside the driver root.
  let link = d.resolvePath(path)
  let dest = d.resolvePath(target)
  try:
    createSymlink(dest, link)
  except CatchableError as e:
    raise newException(StorageError, "Failed to create symlink '" & path & "' -> '" & target & "': " & e.msg)

method isSymlink*(d: AsyncLocalDriver, path: string): Future[bool] {.base, async.} =
  ## Returns true if the file at `path` is a symbolic link.
  let full = d.resolvePath(path)
  try:
    return symlinkExists(full)
  except CatchableError as e:
    raise newException(StorageError, "Failed to check symlink '" & path & "': " & e.msg)

method readLink*(d: AsyncLocalDriver, path: string): Future[string] {.base, async.} =
  ## Returns the target of the symbolic link at `path`, relative to the root.
  let full = d.resolvePath(path)
  try:
    return expandSymlink(full).relativePath(d.root)
  except CatchableError as e:
    raise newException(StorageError, "Failed to read symlink '" & path & "': " & e.msg)

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
  let full = d.resolvePath(path)
  when defined(posix):
    if chmod(full.cstring, Mode(mode)) != 0:
      raise newException(StorageError, "Failed to chmod '" & path & "'")
  else:
    raise newException(StorageError, "chmod is only supported on POSIX")

method chown*(d: AsyncLocalDriver, path: string, uid, gid: int): Future[void] {.base, async.} =
  ## Changes the owner and group of the file at `path`. POSIX-only.
  let full = d.resolvePath(path)
  when defined(posix):
    if chown(full.cstring, Uid(uid), Gid(gid)) != 0:
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
