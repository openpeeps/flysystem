#
# A filesystem API for Nim, inspired by Flysystem
# from the PHP ecosystem.
# 
# (c) 2026 George Lemon | MIT License
#     Made by Humans from OpenPeeps
#     https://github.com/openpeeps/flysystem

import std/[macros, os, memfiles, strutils, tables, options, times]

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
  ## Macro-based pragma to mark methods as abstract (not implemented in the base driver).
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
method readStream*(d: StorageDriver, path: string): MemFile {.abstract.}
method delete*(d: StorageDriver, path: string) {.abstract.}
method exists*(d: StorageDriver, path: string): bool {.abstract.}
method list*(d: StorageDriver, path: string, recursive = false): seq[FileMetadata] {.abstract.}
method move*(d: StorageDriver, src, dest: string) {.abstract.}
method copy*(d: StorageDriver, src, dest: string) {.abstract.}
method makeDir*(d: StorageDriver, path: string) {.abstract.}
method deleteDir*(d: StorageDriver, path: string) {.abstract.}
method setVisibility*(d: StorageDriver, path: string, visibility: Visibility) {.abstract.}
method metadata*(d: StorageDriver, path: string): FileMetadata {.abstract.}

#
# Filesystem — multi-disk abstraction (like Laravel's Storage facade)
#
type
  Filesystem* = ref object
    ## The Filesystem type provides a multi-disk abstraction where you can define multiple "disks"
    ## (storage backends) and perform file operations on them using a unified interface.
    disks: Table[string, StorageDriver]
    default: string

proc newFilesystem*(defaultDisk = "local"): Filesystem =
  ## Creates a new Filesystem instance with an optional default disk name (default is "local").
  Filesystem(default: defaultDisk)

proc addDisk*(fs: Filesystem, name: string, driver: StorageDriver) =
  ## Adds a new disk (storage backend) to the Filesystem. The `name` is used to reference
  ## this disk in file operations.
  fs.disks[name] = driver

proc disk*(fs: Filesystem, name = ""): StorageDriver =
  ## Retrieves a StorageDriver for the specified disk name. If no name is
  ## provided, it returns the default disk.
  let key = if name.len == 0: fs.default else: name
  if key notin fs.disks:
    raise newException(StorageError, "Disk not found: " & key)
  fs.disks[key]

proc write*(fs: Filesystem, path, content: string, visibility = visPrivate) {.inline.} =
  ## Convenience method to write a file to the default disk
  fs.disk().write(path, content, visibility)

proc read*(fs: Filesystem, path: string): string  {.inline.} =
  ## Convenience method to read a file from the default disk
  fs.disk().read(path)

proc exists*(fs: Filesystem, path: string): bool {.inline.} =
  ## Convenience method to check if a file exists on the default disk
  fs.disk().exists(path)

proc delete*(fs: Filesystem, path: string) {.inline.} =
  ## Convenience method to delete a file from the default disk
  fs.disk().delete(path)

template parseYaml*(fs: Filesystem, path: string): untyped =
  ## Convenience method to read and parse a YAML file from the default disk.
  ## 
  ## This template requires `openparser/yaml` to be imported in the caller module to work.
  let content = fs.disk().read(path)
  parseYaml(content)

template parseYaml*[T](fs: Filesystem, path: string, t: typedesc[T]): untyped =
  ## Generic version of parseYaml that returns a typed result. The caller can specify
  ## the expected type (like a config object) and the YAML will be parsed into that type.
  ## 
  ## This template requires `openparser/yaml` to be imported in the caller module to work.
  let content = fs.disk().read(path)
  parseYaml(content, t)

template parseJson*(fs: Filesystem, path: string): untyped =
  ## Convenience method to read and parse a JSON file from the default disk
  ## This template requires `openparser/json` to be imported in the caller module to work.
  let content = fs.disk().read(path)
  fromJson(content)

template parseJson*[T](fs: Filesystem, path: string, t: typedesc[T]): untyped =
  ## Generic version of parseJson that returns a typed result. The caller can specify
  ## the expected type (like a config object) and the JSON will be parsed into that type.
  ## 
  ## This template requires `openparser/json` to be imported in the caller module to work.
  let content = fs.disk().read(path)
  fromJson(content, t)

template parseToml*(fs: Filesystem, path: string): untyped =
  ## Convenience method to read and parse a TOML file from the default disk
  ## 
  ## This template requires `openparser/toml` to be imported in the caller module to work
  let content = fs.disk().read(path)
  parseToml(content)

template parseCsv*(fs: Filesystem, path: string) =
  ## Convenience method to read and parse a CSV file from the default disk.
  ## 
  ## This template requires `openparser/csv` to be imported in the caller module to work.
  discard