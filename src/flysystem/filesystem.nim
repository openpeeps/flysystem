#
# A filesystem API for Nim, inspired by Flysystem
# from the PHP ecosystem.
# 
# (c) 2026 George Lemon | MIT License
#     Made by Humans from OpenPeeps
#     https://github.com/openpeeps/flysystem
import std/tables
import ./core
import ./policy

#
# Filesystem — multi-disk abstraction (like Laravel's Storage facade)
#
type
  Filesystem* = ref object
    ## The Filesystem type provides a multi-disk abstraction where you can define multiple "disks"
    ## (storage backends) and perform file operations on them using a unified interface.
    ## A `PolicyRules` can be attached to each disk to enforce a security layer.
    disks: Table[string, StorageDriver]
    policies: Table[string, PolicyRules]
    default: string

proc newFilesystem*(defaultDisk = "local"): Filesystem =
  ## Creates a new Filesystem instance with an optional default disk name (default is "local").
  Filesystem(default: defaultDisk)

proc addDisk*(fs: Filesystem, name: string, driver: StorageDriver,
    policy: PolicyRules) =
  ## Adds a new disk (storage backend) to the Filesystem, enforcing the given
  ## `policy` on every operation. The `name` is used to reference this disk in
  ## file operations.
  fs.disks[name] = driver
  fs.policies[name] = policy

proc addDisk*(fs: Filesystem, name: string, driver: StorageDriver) =
  ## Adds a new disk (storage backend) to the Filesystem with no policy.
  fs.addDisk(name, driver, defaultPolicyRules())

proc disk*(fs: Filesystem, name = ""): StorageDriver =
  ## Retrieves a StorageDriver for the specified disk name. If no name is
  ## provided, it returns the default disk. When a policy is attached to the
  ## disk, a `FilesystemPolicy` wrapper enforcing it is returned.
  let key = if name.len == 0: fs.default else: name
  if key notin fs.disks:
    raise newException(StorageError, "Disk not found: " & key)
  let policy = fs.policies[key]
  if policy == defaultPolicyRules():
    fs.disks[key]
  else:
    newFilesystemPolicy(fs.disks[key], policy)

proc rawDisk*(fs: Filesystem, name = ""): StorageDriver =
  ## Retrieves the unwrapped StorageDriver for the specified disk name,
  ## bypassing any attached policy.
  let key = if name.len == 0: fs.default else: name
  if key notin fs.disks:
    raise newException(StorageError, "Disk not found: " & key)
  fs.disks[key]

proc diskPolicy*(fs: Filesystem, name = ""): PolicyRules =
  ## Returns the policy attached to the specified disk name.
  let key = if name.len == 0: fs.default else: name
  if key notin fs.policies:
    raise newException(StorageError, "Disk not found: " & key)
  fs.policies[key]

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
