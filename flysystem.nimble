# Package

version       = "0.2.0"
author        = "George Lemon"
description   = "Multi-driver Filesystem. Atomic Writes, Policy Rules, Locks, Multi-disks and more"
license       = "MIT"
srcDir        = "src"


# Dependencies

requires "nim >= 2.0.0"
requires "mimedb >= 0.1.1"
requires "checksums >= 0.2.2"


# feature "useStdStreams":
#   ## Use std/streams instead of std/memfiles for readStream/readLines.
#   ## Compile with -d:features.flysystem.useStdStreams
#   ## (e.g. via `nimble testStreams`).


# Tasks

task test, "Run the test suite":
  exec "nim c -r --hints:off tests/test1.nim"
  exec "nim c -r --hints:off tests/test_policy.nim"
  exec "nim c -r --hints:off tests/test_async.nim"

task testStreams, "Run the test suite with std/streams backend":
  exec "nim c -r --hints:off -d:features.flysystem.useStdStreams tests/test1.nim"
  exec "nim c -r --hints:off -d:features.flysystem.useStdStreams tests/test_policy.nim"

task testAsync, "Run the async test suite":
  exec "nim c -r --hints:off tests/test_async.nim"
