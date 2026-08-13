#
# A filesystem API for Nim, inspired by Flysystem
# from the PHP ecosystem.
# 
# (c) 2026 George Lemon | MIT License
#     Made by Humans from OpenPeeps
#     https://github.com/openpeeps/flysystem
import std/[os, strutils, options, times, memfiles]
import pkg/mimedb
import ./core

type
  PolicyError* = object of StorageError
    ## Raised when an operation violates a filesystem policy. Carries the
    ## offending `operation` and the `rule` that was violated.
    operation*: string
    rule*: string

  PolicyRules* = object
    ## Configurable rules enforced by a `FilesystemPolicy`. Zero / empty
    ## values mean "no restriction".
    readOnly*: bool
      ## deny all mutating operations (write, delete, move, ...)
    maxFileSize*: int64
      ## maximum bytes for a single file; 0 = unlimited
    maxPathLength*: int
      ## maximum characters in a path; 0 = unlimited
    maxDepth*: int
      ## maximum number of path segments; 0 = unlimited
    denyHiddenFiles*: bool
      ## block creation of hidden files and filter them from listings
    allowedExtensions*: seq[string]
      ## allowed file extensions without the leading dot; empty = allow all
    allowedMimeTypes*: seq[string]
      ## allowed MIME types (inferred from the extension via mimedb);
      ## empty = allow all

  FilesystemPolicy* = ref object of StorageDriver
    ## A security layer wrapping an underlying `StorageDriver`. Every
    ## operation is checked against a set of `PolicyRules` before being
    ## delegated, and violations raise a `PolicyError`.
    inner: StorageDriver
    rules: PolicyRules

proc defaultPolicyRules*(): PolicyRules =
  ## Returns a policy with no restrictions (everything allowed).
  PolicyRules()

proc newFilesystemPolicy*(inner: StorageDriver,
    rules: PolicyRules = defaultPolicyRules()): FilesystemPolicy =
  ## Wraps `inner` with the given `rules`.
  FilesystemPolicy(inner: inner, rules: rules)

proc inner*(p: FilesystemPolicy): StorageDriver =
  ## Returns the underlying driver.
  p.inner

proc rules*(p: FilesystemPolicy): PolicyRules =
  ## Returns the rules enforced by this policy.
  p.rules

proc policyError(operation, rule, detail: string) {.noReturn.} =
  var e = newException(PolicyError,
    "policy violation [" & rule & "]: " & operation & " " & detail)
  e.operation = operation
  e.rule = rule
  raise e

proc checkWritable(p: FilesystemPolicy, operation: string) =
  if p.rules.readOnly:
    policyError(operation, "readOnly", "is not allowed in read-only mode")

proc checkPath(p: FilesystemPolicy, operation, path: string) =
  if p.rules.maxPathLength > 0 and path.len > p.rules.maxPathLength:
    policyError(operation, "maxPathLength",
      "path of " & $path.len & " chars exceeds limit of " & $p.rules.maxPathLength)
  if p.rules.maxDepth > 0:
    let depth = path.split({DirSep, AltSep}).len
    if depth > p.rules.maxDepth:
      policyError(operation, "maxDepth",
        "path depth of " & $depth & " exceeds limit of " & $p.rules.maxDepth)

proc isHidden(path: string): bool =
  let name = extractFilename(path)
  name.len > 0 and name[0] == '.'

proc checkHidden(p: FilesystemPolicy, operation, path: string) =
  if p.rules.denyHiddenFiles and isHidden(path):
    policyError(operation, "denyHiddenFiles", "hidden path: '" & path & "'")

proc checkCreate(p: FilesystemPolicy, operation, path: string) =
  ## Enforces create-target rules: hidden files, allowed extensions and
  ## allowed MIME types.
  p.checkHidden(operation, path)
  if p.rules.allowedExtensions.len > 0:
    var ext = splitFile(path).ext
    if ext.len > 0:
      ext = ext[1..^1]
    if ext.len == 0 or ext notin p.rules.allowedExtensions:
      policyError(operation, "allowedExtensions",
        "extension not allowed: '" & path & "'")
  if p.rules.allowedMimeTypes.len > 0:
    let ext = splitFile(path).ext
    let mime =
      if ext.len > 0: getMimeType(ext[1..^1]).get("application/octet-stream")
      else: "application/octet-stream"
    if mime notin p.rules.allowedMimeTypes:
      policyError(operation, "allowedMimeTypes",
        "mime type not allowed: '" & path & "' (" & mime & ")")

proc checkSize(p: FilesystemPolicy, operation: string, size: int64) =
  if p.rules.maxFileSize > 0 and size > p.rules.maxFileSize:
    policyError(operation, "maxFileSize",
      $size & " bytes exceeds limit of " & $p.rules.maxFileSize)

proc checkTree(p: FilesystemPolicy, operation, src, dest: string) =
  ## Validates every file that would land under `dest` against the create
  ## rules, since the inner driver recurses on its own.
  for item in p.inner.list(src, recursive = true):
    if not item.isDir:
      let rel =
        if src.len == 0: item.path
        else: item.path.relativePath(src)
      let destPath = dest / rel
      p.checkPath(operation, destPath)
      p.checkCreate(operation, destPath)

#
# Read operations
#
method read*(p: FilesystemPolicy, path: string): string =
  p.checkPath("read", path)
  p.inner.read(path)

method readStream*(p: FilesystemPolicy, path: string): MemFile =
  p.checkPath("readStream", path)
  p.inner.readStream(path)

method exists*(p: FilesystemPolicy, path: string): bool =
  p.checkPath("exists", path)
  p.inner.exists(path)

method list*(p: FilesystemPolicy, path: string,
    recursive = false): seq[FileMetadata] =
  p.checkPath("list", path)
  result = p.inner.list(path, recursive)
  if p.rules.denyHiddenFiles:
    for i in countdown(result.high, 0):
      if isHidden(result[i].path):
        result.delete(i)

method search*(p: FilesystemPolicy, pattern: string): seq[string] =
  p.checkPath("search", pattern)
  result = p.inner.search(pattern)
  if p.rules.denyHiddenFiles:
    for i in countdown(result.high, 0):
      if isHidden(result[i]):
        result.delete(i)

method visibility*(p: FilesystemPolicy, path: string): Visibility =
  p.checkPath("visibility", path)
  p.inner.visibility(path)

method metadata*(p: FilesystemPolicy, path: string): FileMetadata =
  p.checkPath("metadata", path)
  p.inner.metadata(path)

method size*(p: FilesystemPolicy, path: string): int64 =
  p.checkPath("size", path)
  p.inner.size(path)

method lastModified*(p: FilesystemPolicy, path: string): Time =
  p.checkPath("lastModified", path)
  p.inner.lastModified(path)

method checksum*(p: FilesystemPolicy, path: string): string =
  p.checkPath("checksum", path)
  p.inner.checksum(path)

method mimeType*(p: FilesystemPolicy, path: string): string =
  p.checkPath("mimeType", path)
  p.inner.mimeType(path)

#
# Mutating operations
#
method write*(p: FilesystemPolicy, path, content: string,
    visibility = visPrivate) =
  p.checkWritable("write")
  p.checkPath("write", path)
  p.checkCreate("write", path)
  p.checkSize("write", content.len.int64)
  p.inner.write(path, content, visibility)

method append*(p: FilesystemPolicy, path, content: string) =
  p.checkWritable("append")
  p.checkPath("append", path)
  p.checkCreate("append", path)
  var existing: int64 = 0
  if p.inner.exists(path):
    existing = p.inner.size(path)
  p.checkSize("append", existing + content.len)
  p.inner.append(path, content)

method writeStream*(p: FilesystemPolicy, path: string, src: File) =
  p.checkWritable("writeStream")
  p.checkPath("writeStream", path)
  p.checkCreate("writeStream", path)
  p.checkSize("writeStream", getFileSize(src))
  p.inner.writeStream(path, src)

method appendStream*(p: FilesystemPolicy, path: string, src: File) =
  p.checkWritable("appendStream")
  p.checkPath("appendStream", path)
  p.checkCreate("appendStream", path)
  var existing: int64 = 0
  if p.inner.exists(path):
    existing = p.inner.size(path)
  p.checkSize("appendStream", existing + getFileSize(src))
  p.inner.appendStream(path, src)

method delete*(p: FilesystemPolicy, path: string) =
  p.checkWritable("delete")
  p.checkPath("delete", path)
  p.inner.delete(path)

method move*(p: FilesystemPolicy, src, dest: string) =
  p.checkWritable("move")
  p.checkPath("move", src)
  p.checkPath("move", dest)
  p.checkCreate("move", dest)
  p.inner.move(src, dest)

method copy*(p: FilesystemPolicy, src, dest: string) =
  p.checkWritable("copy")
  p.checkPath("copy", src)
  p.checkPath("copy", dest)
  p.checkCreate("copy", dest)
  p.inner.copy(src, dest)

method makeDir*(p: FilesystemPolicy, path: string) =
  p.checkWritable("makeDir")
  p.checkPath("makeDir", path)
  p.checkHidden("makeDir", path)
  p.inner.makeDir(path)

method deleteDir*(p: FilesystemPolicy, path: string, force = false) =
  p.checkWritable("deleteDir")
  p.checkPath("deleteDir", path)
  p.inner.deleteDir(path, force)

method touch*(p: FilesystemPolicy, path: string) =
  p.checkWritable("touch")
  p.checkPath("touch", path)
  p.checkCreate("touch", path)
  p.inner.touch(path)

method copyDir*(p: FilesystemPolicy, src, dest: string) =
  p.checkWritable("copyDir")
  p.checkPath("copyDir", src)
  p.checkPath("copyDir", dest)
  p.checkHidden("copyDir", dest)
  p.checkTree("copyDir", src, dest)
  p.inner.copyDir(src, dest)

method moveDir*(p: FilesystemPolicy, src, dest: string) =
  p.checkWritable("moveDir")
  p.checkPath("moveDir", src)
  p.checkPath("moveDir", dest)
  p.checkHidden("moveDir", dest)
  p.checkTree("moveDir", src, dest)
  p.inner.moveDir(src, dest)

method setVisibility*(p: FilesystemPolicy, path: string,
    visibility: Visibility) =
  p.checkWritable("setVisibility")
  p.checkPath("setVisibility", path)
  p.inner.setVisibility(path, visibility)
