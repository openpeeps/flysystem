#
# A filesystem API for Nim, inspired by Flysystem
# from the PHP ecosystem.
# 
# (c) 2026 George Lemon | MIT License
#     Made by Humans from OpenPeeps
#     https://github.com/openpeeps/flysystem
import std/[os, strutils, memfiles]
import ./core

#
# Local Driver implementation
#
proc resolvePath(d: LocalDriver, path: string): string =
  ## Resolves a relative path against the runtime root.
  ## 
  ## Prevents path traversal outside the root for security
  let resolved = normalizedPath(d.root / path)
  if not resolved.startsWith(d.root):
    # prevent path traversal outside the root
    raise newException(StorageError, "Path traversal detected: " & path)
  resolved

proc newLocalDriver*(root: string): LocalDriver =
  ## Creates a LocalDriver. `root` is an absolute runtime path.
  ## Example: pass in the value of an env var or config key at startup.
  result = LocalDriver(root: expandTilde(root).absolutePath)
  if not dirExists(result.root):
    createDir(result.root)

method write*(d: LocalDriver, path, content: string,
    visibility = visPrivate) =
  let full = d.resolvePath(path)
  createDir(full.parentDir)
  writeFile(full, content)
  # when defined(posix):
  #   import std/posix
  #   let mode = if visibility == visPublic: 0o644 else: 0o600
  #   discard chmod(full.cstring, Mode(mode))

method read*(d: LocalDriver, path: string): string =
  ## Reads a file from the local filesystem at the specified path.
  ## 
  ## The path is resolved against the driver's root directory.
  readFile(d.resolvePath(path))

method readStream*(d: LocalDriver, path: string): MemFile =
  ## Efficiently reads a file as a stream using memfiles, which allows
  ## for handling large files without loading them entirely into memory
  memfiles.open(d.resolvePath(path), fmRead)

method delete*(d: LocalDriver, path: string) =
  ## Deletes a file from the local filesystem at the specified path.
  ## 
  ## The path is resolved against the driver's root directory.
  removeFile(d.resolvePath(path))

method exists*(d: LocalDriver, path: string): bool =
  ## Checks if a file or directory exists at the specified path on the
  ## local filesystem.
  let full = d.resolvePath(path)
  fileExists(full) or dirExists(full)

method list*(d: LocalDriver, path: string,
    recursive: static bool = false): seq[FileMetadata] =
  ## Lists files and directories at the specified path. If `recursive` is true,
  ## it will list all files and directories recursively. Returns a sequence of FileMetadata objects.
  let full = d.resolvePath(path)
  when recursive:
    for entry in walkDirRec(full):
      let p = entry
      result.add FileMetadata(path: p.relativePath(d.root),
        size: getFileSize(p), lastModified: getLastModificationTime(p),
        isDir: dirExists(p))
  else:
    for entry in walkDir(full):
      result.add FileMetadata(path: entry.path.relativePath(d.root),
        size: (if entry.kind == pcFile: getFileSize(entry.path) else: 0),
        lastModified: getLastModificationTime(entry.path),
        isDir: entry.kind in {pcDir, pcLinkToDir})

method move*(d: LocalDriver, src, dest: string) =
  ## Moves a file from `src` to `dest` on the local filesystem.
  ## 
  ## Creates parent directories if needed.
  moveFile(d.resolvePath(src), d.resolvePath(dest))

method copy*(d: LocalDriver, src, dest: string) =
  ## Copies a file from `src` to `dest` on the local filesystem.
  ## 
  ## Creates parent directories if needed.
  let destFull = d.resolvePath(dest)
  createDir(destFull.parentDir)
  copyFile(d.resolvePath(src), destFull)

method makeDir*(d: LocalDriver, path: string) =
  ## Creates a directory at the specified path. Creates parent
  ## directories if needed.
  createDir(d.resolvePath(path))

method deleteDir*(d: LocalDriver, path: string) =
  ## Deletes a directory at the specified path. Deletes recursively
  ## if the directory is not empty.
  removeDir(d.resolvePath(path))

method metadata*(d: LocalDriver, path: string): FileMetadata =
  ## Retrieves metadata for a file or directory at the specified path,
  ## including size, last modified time, and whether it's a directory.
  let full = d.resolvePath(path)
  FileMetadata(
    path: path,
    size: getFileSize(full),
    lastModified: getLastModificationTime(full),
    isDir: dirExists(full)
  )