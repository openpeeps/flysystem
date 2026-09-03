#
# A filesystem API for Nim, inspired by Flysystem
# from the PHP ecosystem.
# 
# (c) 2026 George Lemon | MIT License
#     Made by Humans from OpenPeeps
#     https://github.com/openpeeps/flysystem

import std/[macros, times]

when defined(features.flysystem.useStdStreams):
  import std/streams
  type FlysystemStream* = Stream
else:
  import std/memfiles
  type FlysystemStream* = MemFile

type        
  Visibility* = enum
    ## Defines file visibility options for storage operations. This can be used
    ## to set permissions or access controls
    visPublic = "public"
    visPrivate = "private"

  FileMetadata* = object
    ## Metadata for a file or directory, including its path, size, last modified time,
    ## visibility, and whether it's a directory. This is returned by the `metadata` method
    ## and the `list` method of storage drivers to provide information about files and directories
    path*: string
    size*: int64
    lastModified*: Time
    visibility*: Visibility
    isDir*: bool

#
# Driver abstraction
#
type
  StorageDriver* = ref object of RootObj
    ## The StorageDriver type is an abstract base for different storage implementations.
    ## Concrete drivers (like LocalDriver) will implement the required file operations
    root*: string

  LocalDriver* = ref object of StorageDriver
    ## Filesystem driver using an absolute runtime root.
    ## The root is set at runtime (from config/env), NOT at compile time.

  StorageError* = object of CatchableError

macro abstract*(x: untyped): untyped =
  ## Macro-based pragma to mark methods as abstract
  x[^3] = nnkPragma.newTree(ident"base")
  var body = newStmtList()
  add body, quote do:
    raise newException(StorageError, "Not implemented")
  x[^1] = body
  x

#
# Abstract methods that all drivers must implement
#
method write*(d: StorageDriver, path, content: string, visibility = visPrivate) {.abstract.}
method read*(d: StorageDriver, path: string): string {.abstract.}
method readStream*(d: StorageDriver, path: string): FlysystemStream {.abstract.}
method delete*(d: StorageDriver, path: string) {.abstract.}
method exists*(d: StorageDriver, path: string): bool {.abstract.}
method list*(d: StorageDriver, path: string, recursive = false): seq[FileMetadata] {.abstract.}
method move*(d: StorageDriver, src, dest: string) {.abstract.}
method copy*(d: StorageDriver, src, dest: string) {.abstract.}
method makeDir*(d: StorageDriver, path: string) {.abstract.}
method deleteDir*(d: StorageDriver, path: string, force = false) {.abstract.}
method touch*(d: StorageDriver, path: string) {.abstract.}
method copyDir*(d: StorageDriver, src, dest: string) {.abstract.}
method moveDir*(d: StorageDriver, src, dest: string) {.abstract.}
method search*(d: StorageDriver, pattern: string): seq[string] {.abstract.}
method setVisibility*(d: StorageDriver, path: string, visibility: Visibility) {.abstract.}
method visibility*(d: StorageDriver, path: string): Visibility {.abstract.}
method metadata*(d: StorageDriver, path: string): FileMetadata {.abstract.}
method size*(d: StorageDriver, path: string): int64 {.base.} =
  ## Default implementation via `metadata` — drivers may override for efficiency.
  d.metadata(path).size
method lastModified*(d: StorageDriver, path: string): Time {.base.} =
  ## Default implementation via `metadata`.
  d.metadata(path).lastModified
method append*(d: StorageDriver, path, content: string) {.abstract.}
method writeStream*(d: StorageDriver, path: string, src: File) {.abstract.}
method appendStream*(d: StorageDriver, path: string, src: File) {.abstract.}
method checksum*(d: StorageDriver, path: string): string {.abstract.}
method mimeType*(d: StorageDriver, path: string): string {.abstract.}