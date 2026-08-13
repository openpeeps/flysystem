#
# A filesystem API for Nim, inspired by Flysystem
# from the PHP ecosystem.
# 
# (c) 2026 George Lemon | MIT License
#     Made by Humans from OpenPeeps
#     https://github.com/openpeeps/flysystem
import std/[os, strutils, memfiles, options, times, syncio, posix]
import pkg/mimedb
import checksums/md5
import ./core

#
# Local Driver implementation
#
proc resolvePath(d: LocalDriver, path: string): string =
  ## Resolves a relative path against the runtime root. Absolute paths are
  ## normalized as-is, as long as they stay inside the root.
  ## 
  ## Prevents path traversal outside the root for security
  let resolved = normalizedPath(if isAbsolute(path): path else: d.root / path)
  if not resolved.startsWith(d.root):
    # prevent path traversal outside the root
    raise newException(StorageError, "Path traversal detected: " & path)
  resolved

proc streamCopy(dst, src: File) =
  ## Copies the contents of `src` (from its current position) to `dst`.
  var buf: array[8192, byte]
  while true:
    let n = src.readBuffer(addr buf[0], buf.len)
    if n <= 0: break
    discard dst.writeBuffer(addr buf[0], n)

var tmpCounter {.threadvar.}: int64

proc tempPath(full: string): string =
  ## Returns a unique temporary path in the same directory as `full`,
  ## suitable for atomic writes.
  inc tmpCounter
  full & ".tmp" & $getCurrentProcessId() & "." & $tmpCounter

proc newLocalDriver*(root: string): LocalDriver =
  ## Creates a LocalDriver. `root` is an absolute runtime path.
  ## Example: pass in the value of an env var or config key at startup.
  result = LocalDriver(root: expandTilde(root).absolutePath)
  if not dirExists(result.root):
    createDir(result.root)

method write*(d: LocalDriver, path, content: string,
    visibility = visPrivate) =
  ## Writes `content` to the file at `path`. The write is atomic: content is
  ## first written to a temporary file in the same directory and then renamed
  ## over the target, so a crash mid-write never corrupts the file.
  let full = d.resolvePath(path)
  try:
    createDir(full.parentDir)
    let tmp = tempPath(full)
    writeFile(tmp, content)
    d.setVisibility(tmp, visibility)
    moveFile(tmp, full)
  except CatchableError as e:
    raise newException(StorageError, "Failed to write '" & path & "': " & e.msg)

method read*(d: LocalDriver, path: string): string =
  ## Reads a file from the local filesystem at the specified path.
  ## 
  ## The path is resolved against the driver's root directory.
  let full = d.resolvePath(path)
  try:
    readFile(full)
  except CatchableError as e:
    raise newException(StorageError, "Failed to read '" & path & "': " & e.msg)

method readStream*(d: LocalDriver, path: string): MemFile =
  ## Efficiently reads a file as a stream using memfiles, which allows
  ## for handling large files without loading them entirely into memory.
  ## An empty file yields a MemFile with `size == 0` and `mem == nil`, which
  ## holds no resources and does not need to be `close`d.
  let full = d.resolvePath(path)
  try:
    if getFileSize(full) > 0:
      result = memfiles.open(full, fmRead)
    else:
      result = default(MemFile)
      when not defined(windows):
        result.handle = -1
  except CatchableError as e:
    raise newException(StorageError, "Failed to read stream '" & path & "': " & e.msg)

method writeStream*(d: LocalDriver, path: string, src: File) =
  ## Streams the contents of an open file handle `src` to the specified path.
  ## Parent directories are created if needed. The write is atomic.
  let full = d.resolvePath(path)
  try:
    createDir(full.parentDir)
    let tmp = tempPath(full)
    var dst = syncio.open(tmp, fmWrite)
    streamCopy(dst, src)
    dst.close()
    d.setVisibility(tmp, visPrivate)
    moveFile(tmp, full)
  except CatchableError as e:
    raise newException(StorageError, "Failed to write stream '" & path & "': " & e.msg)

method append*(d: LocalDriver, path, content: string) =
  ## Appends `content` to the file at the specified path. Creates the file
  ## (and parent directories) if it does not exist yet.
  let full = d.resolvePath(path)
  try:
    if not fileExists(full):
      createDir(full.parentDir)
    var f = syncio.open(full, fmAppend)
    f.write(content)
    f.close()
  except CatchableError as e:
    raise newException(StorageError, "Failed to append to '" & path & "': " & e.msg)

method appendStream*(d: LocalDriver, path: string, src: File) =
  ## Appends the contents of an open file handle `src` to the file at the
  ## specified path. Creates the file (and parent directories) if it does
  ## not exist yet.
  let full = d.resolvePath(path)
  try:
    if not fileExists(full):
      createDir(full.parentDir)
    var f = syncio.open(full, fmAppend)
    streamCopy(f, src)
    f.close()
  except CatchableError as e:
    raise newException(StorageError, "Failed to append stream to '" & path & "': " & e.msg)

method delete*(d: LocalDriver, path: string) =
  ## Deletes a file from the local filesystem at the specified path.
  ## 
  ## The path is resolved against the driver's root directory.
  let full = d.resolvePath(path)
  try:
    removeFile(full)
  except CatchableError as e:
    raise newException(StorageError, "Failed to delete '" & path & "': " & e.msg)

method exists*(d: LocalDriver, path: string): bool =
  ## Checks if a file or directory exists at the specified path on the
  ## local filesystem.
  let full = d.resolvePath(path)
  try:
    fileExists(full) or dirExists(full)
  except CatchableError as e:
    raise newException(StorageError, "Failed to check existence of '" & path & "': " & e.msg)

proc collectEntries(d: LocalDriver, full: string, res: var seq[FileMetadata]) =
  ## Recursively collects entries, including empty directories.
  for entry in walkDir(full):
    res.add FileMetadata(
      path: entry.path.relativePath(d.root),
      size: (if entry.kind == pcFile: getFileSize(entry.path) else: 0),
      lastModified: getLastModificationTime(entry.path),
      isDir: entry.kind in {pcDir, pcLinkToDir})
    if entry.kind in {pcDir, pcLinkToDir}:
      collectEntries(d, entry.path, res)

method list*(d: LocalDriver, path: string,
    recursive: static bool = false): seq[FileMetadata] =
  ## Lists files and directories at the specified path. If `recursive` is true,
  ## it will list all files and directories recursively, including empty
  ## directories. Returns a sequence of FileMetadata objects.
  let full = d.resolvePath(path)
  try:
    when recursive:
      collectEntries(d, full, result)
    else:
      for entry in walkDir(full):
        result.add FileMetadata(path: entry.path.relativePath(d.root),
          size: (if entry.kind == pcFile: getFileSize(entry.path) else: 0),
          lastModified: getLastModificationTime(entry.path),
          isDir: entry.kind in {pcDir, pcLinkToDir})
  except CatchableError as e:
    raise newException(StorageError, "Failed to list '" & path & "': " & e.msg)

method move*(d: LocalDriver, src, dest: string) =
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

method copy*(d: LocalDriver, src, dest: string) =
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

method makeDir*(d: LocalDriver, path: string) =
  ## Creates a directory at the specified path. Creates parent
  ## directories if needed.
  let full = d.resolvePath(path)
  try:
    createDir(full)
  except CatchableError as e:
    raise newException(StorageError, "Failed to create directory '" & path & "': " & e.msg)

method deleteDir*(d: LocalDriver, path: string, force = false) =
  ## Deletes a directory at the specified path. If `force` is false, only an
  ## empty directory can be deleted; otherwise a `StorageError` is raised.
  ## If `force` is true, the directory is deleted recursively.
  let full = d.resolvePath(path)
  try:
    if force:
      removeDir(full)
    else:
      if not dirExists(full):
        return
      for _ in walkDir(full):
        raise newException(StorageError, "Directory not empty: " & path)
      removeDir(full)
  except StorageError:
    raise
  except CatchableError as e:
    raise newException(StorageError, "Failed to delete directory '" & path & "': " & e.msg)

method setVisibility*(d: LocalDriver, path: string, visibility: Visibility) =
  ## Sets the file visibility. `visPublic` maps to world-readable permissions
  ## (0o644), `visPrivate` to user-only (0o600).
  let full = d.resolvePath(path)
  let perms =
    if visibility == visPublic:
      {fpUserRead, fpUserWrite, fpGroupRead, fpOthersRead}
    else:
      {fpUserRead, fpUserWrite}
  try:
    setFilePermissions(full, perms)
  except CatchableError as e:
    raise newException(StorageError, "Failed to set visibility of '" & path & "': " & e.msg)

method visibility*(d: LocalDriver, path: string): Visibility =
  ## Returns the visibility of the file at the specified path, based on
  ## its actual filesystem permissions.
  let full = d.resolvePath(path)
  try:
    if fpOthersRead in getFilePermissions(full): visPublic else: visPrivate
  except CatchableError as e:
    raise newException(StorageError, "Failed to get visibility of '" & path & "': " & e.msg)

method metadata*(d: LocalDriver, path: string): FileMetadata =
  ## Retrieves metadata for a file or directory at the specified path,
  ## including size, last modified time, and whether it's a directory.
  let full = d.resolvePath(path)
  try:
    FileMetadata(
      path: full.relativePath(d.root),
      size: getFileSize(full),
      lastModified: getLastModificationTime(full),
      isDir: dirExists(full)
    )
  except CatchableError as e:
    raise newException(StorageError, "Failed to retrieve metadata of '" & path & "': " & e.msg)

method size*(d: LocalDriver, path: string): int64 =
  ## Returns the size in bytes of the file at the specified path.
  let full = d.resolvePath(path)
  try:
    getFileSize(full)
  except CatchableError as e:
    raise newException(StorageError, "Failed to get size of '" & path & "': " & e.msg)

method lastModified*(d: LocalDriver, path: string): times.Time =
  ## Returns the last modification time of the file at the specified path.
  let full = d.resolvePath(path)
  try:
    getLastModificationTime(full)
  except CatchableError as e:
    raise newException(StorageError, "Failed to get last modified time of '" & path & "': " & e.msg)

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
  let full = d.resolvePath(path)
  try:
    createDir(full.parentDir)
    if not fileExists(full):
      writeFile(full, "")
    setLastModificationTime(full, getTime())
  except CatchableError as e:
    raise newException(StorageError, "Failed to touch '" & path & "': " & e.msg)

iterator readLines*(d: LocalDriver, path: string): string =
  ## Iterates over the lines of the file at `path` using a memory-mapped read.
  ## A single internal buffer is reused across lines, so no per-line allocations
  ## happen. The yielded string is only valid until the next iteration — copy it
  ## if you need to keep it.
  let full = d.resolvePath(path)
  var size: int64
  try:
    size = getFileSize(full)
  except CatchableError as e:
    raise newException(StorageError, "Failed to read '" & path & "': " & e.msg)
  if size > 0:
    var mf: MemFile
    try:
      mf = memfiles.open(full, fmRead)
    except CatchableError as e:
      raise newException(StorageError, "Failed to read '" & path & "': " & e.msg)
    var buf = newString(0)
    for line in lines(mf, buf):
      yield line
    close(mf)

method copyDir*(d: LocalDriver, src, dest: string) =
  ## Recursively copies a directory from `src` to `dest`, including empty
  ## directories. Creates parent directories if needed.
  let srcFull = d.resolvePath(src)
  let destFull = d.resolvePath(dest)
  try:
    createDir(destFull)
    for entry in walkDir(srcFull):
      let target = destFull / extractFilename(entry.path)
      case entry.kind
      of pcDir:
        d.copyDir(entry.path, target)
      of pcFile:
        copyFile(entry.path, target)
      else:
        discard
  except CatchableError as e:
    raise newException(StorageError, "Failed to copy directory '" & src & "' to '" & dest & "': " & e.msg)

method moveDir*(d: LocalDriver, src, dest: string) =
  ## Moves a directory from `src` to `dest`. Creates parent directories if
  ## needed.
  let srcFull = d.resolvePath(src)
  let destFull = d.resolvePath(dest)
  try:
    createDir(destFull.parentDir)
    moveDir(srcFull, destFull)
  except CatchableError as e:
    raise newException(StorageError, "Failed to move directory '" & src & "' to '" & dest & "': " & e.msg)

method createSymlink*(d: LocalDriver, path, target: string) =
  ## Creates a symbolic link at `path` pointing to `target`. `target` must
  ## resolve inside the driver root.
  let link = d.resolvePath(path)
  let dest = d.resolvePath(target)
  try:
    createSymlink(dest, link)
  except CatchableError as e:
    raise newException(StorageError, "Failed to create symlink '" & path & "' -> '" & target & "': " & e.msg)

method isSymlink*(d: LocalDriver, path: string): bool =
  ## Returns true if the file at `path` is a symbolic link.
  let full = d.resolvePath(path)
  try:
    symlinkExists(full)
  except CatchableError as e:
    raise newException(StorageError, "Failed to check symlink '" & path & "': " & e.msg)

method readLink*(d: LocalDriver, path: string): string =
  ## Returns the target of the symbolic link at `path`, relative to the root.
  let full = d.resolvePath(path)
  try:
    expandSymlink(full).relativePath(d.root)
  except CatchableError as e:
    raise newException(StorageError, "Failed to read symlink '" & path & "': " & e.msg)

template withLock*(d: LocalDriver, path: string, body: untyped) =
  ## Executes `body` while holding an exclusive advisory lock on the file at
  ## `path`. The file is created if it does not exist. POSIX-only.
  let full = d.resolvePath(path)
  if not fileExists(full):
    createDir(full.parentDir)
    writeFile(full, "")
  var lockFile = syncio.open(full, fmReadWriteExisting)
  when defined(posix):
    var fl: Tflock
    fl.l_type = F_WRLCK.cshort
    fl.l_whence = SEEK_SET.cshort
    fl.l_start = 0
    fl.l_len = 0
    if fcntl(lockFile.getOsFileHandle(), F_SETLKW, addr fl) != 0:
      lockFile.close()
      raise newException(StorageError, "Failed to acquire lock on '" & path & "'")
  try:
    body
  finally:
    when defined(posix):
      var ul: Tflock
      ul.l_type = F_UNLCK.cshort
      ul.l_whence = SEEK_SET.cshort
      discard fcntl(lockFile.getOsFileHandle(), F_SETLK, addr ul)
    lockFile.close()

method search*(d: LocalDriver, pattern: string): seq[string] =
  ## Returns paths (relative to the root) matching the glob `pattern`,
  ## e.g. `"*.txt"` or `"sub/*.log"`.
  let (dir, name) = splitPath(pattern)
  let base = if dir.len == 0: d.root else: d.resolvePath(dir)
  try:
    for p in walkPattern(base / name):
      result.add p.relativePath(d.root)
  except CatchableError as e:
    raise newException(StorageError, "Failed to search '" & pattern & "': " & e.msg)

method diskUsage*(d: LocalDriver): tuple[total, free, used: int64] =
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

method chmod*(d: LocalDriver, path: string, mode: int) =
  ## Sets the file permission bits of `path` to `mode` (e.g. 0o644).
  ## POSIX-only.
  let full = d.resolvePath(path)
  when defined(posix):
    if chmod(full.cstring, Mode(mode)) != 0:
      raise newException(StorageError, "Failed to chmod '" & path & "'")
  else:
    raise newException(StorageError, "chmod is only supported on POSIX")

method chown*(d: LocalDriver, path: string, uid, gid: int) =
  ## Changes the owner and group of the file at `path`. POSIX-only.
  let full = d.resolvePath(path)
  when defined(posix):
    if chown(full.cstring, Uid(uid), Gid(gid)) != 0:
      raise newException(StorageError, "Failed to chown '" & path & "'")
  else:
    raise newException(StorageError, "chown is only supported on POSIX")
