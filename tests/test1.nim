import unittest
import os, strutils, sequtils
import flysystem

test "local driver basic file ops":
  let root = joinPath(getCurrentDir() / "tests" / "tmp_flysystem_test")
  # ensure a clean test root
  if dirExists(root):
    removeDir(root)
  
  createDir(root)

  let d = newLocalDriver(root)
  check dirExists(root)

  # write / read / exists
  check not d.exists("foo.txt")
  d.write("foo.txt", "hello world")
  check d.exists("foo.txt")
  check d.read("foo.txt") == "hello world"

  # metadata
  let m = d.metadata("foo.txt")
  check m.path == "foo.txt"
  check not m.isDir

  # move
  d.makeDir("sub")
  d.move("foo.txt", "sub/renamed.txt")
  check not d.exists("foo.txt")
  check d.exists("sub/renamed.txt")

  # copy
  d.copy("sub/renamed.txt", "copy_of_renamed.txt")
  check d.exists("copy_of_renamed.txt")

  # list (recursive)
  let items = d.list("", recursive = true)
  var foundRenamed = false
  var foundCopy = false
  for it in items:
    if it.path == "sub/renamed.txt":
      foundRenamed = true
    if it.path == "copy_of_renamed.txt":
      foundCopy = true
  check foundRenamed
  check foundCopy

  # cleanup
  if dirExists(root):
    removeDir(root)

test "prevent path traversal":
  let root = joinPath(getCurrentDir() / "tests" / "tmp_flysystem_test_traversal")
  # ensure a clean test root
  if dirExists(root):
    removeDir(root)
  
  createDir(root)

  let d = newLocalDriver(root)
  check dirExists(root)

  # attempt path traversal
  try:
    d.write("../traversal.txt", "should not be allowed")
    assert false, "Expected an exception for path traversal"
  except StorageError as e:
    check e.msg == "Path traversal detected: ../traversal.txt"

  # cleanup
  if dirExists(root):
    removeDir(root)