# Package

version       = "0.1.1"
author        = "George Lemon"
description   = "Multi-driver Filesystem. Atomic Writes, Policy Rules, Locks, Multi-disks and more"
license       = "MIT"
srcDir        = "src"


# Dependencies

requires "nim >= 2.0.0"
requires "mimedb >= 0.1.1"
requires "checksums >= 0.2.2"


# Tasks

task test, "Run the test suite":
  exec "nim c -r --hints:off tests/test1.nim"
  exec "nim c -r --hints:off tests/test_policy.nim"
