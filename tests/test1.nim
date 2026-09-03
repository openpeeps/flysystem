import unittest
import os, strutils, times, posix
when defined(features.flysystem.useStdStreams):
  import std/streams
else:
  import std/memfiles
import std/syncio
import checksums/md5
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

  # glob search is sandboxed too
  try:
    discard d.search("../evil/*.txt")
    assert false, "Expected an exception for path traversal in search"
  except StorageError as e:
    check "Path traversal detected" in e.msg

  # cleanup
  if dirExists(root):
    removeDir(root)

test "visibility":
  let root = joinPath(getCurrentDir() / "tests" / "tmp_flysystem_test_visibility")
  if dirExists(root):
    removeDir(root)
  createDir(root)

  let d = newLocalDriver(root)
  d.write("secret.txt", "top secret", visPrivate)
  check d.visibility("secret.txt") == visPrivate

  d.setVisibility("secret.txt", visPublic)
  check d.visibility("secret.txt") == visPublic

  d.write("public.txt", "hello", visPublic)
  check d.visibility("public.txt") == visPublic

  # default visibility is private
  d.write("implicit.txt", "hi")
  check d.visibility("implicit.txt") == visPrivate

  if dirExists(root):
    removeDir(root)

test "append & stream ops":
  let root = joinPath(getCurrentDir() / "tests" / "tmp_flysystem_test_stream")
  if dirExists(root):
    removeDir(root)
  createDir(root)

  let d = newLocalDriver(root)

  # append
  d.append("log.txt", "line1\n")
  d.append("log.txt", "line2\n")
  check d.read("log.txt") == "line1\nline2\n"

  # append into a nested (non-existing) directory
  d.append("sub/deep.log", "x")
  check d.exists("sub/deep.log")

  # writeStream from an open handle
  writeFile(root / "src.bin", "streamed data")
  var src = syncio.open(root / "src.bin", fmRead)
  d.writeStream("dst.bin", src)
  src.close()
  check d.read("dst.bin") == "streamed data"

  # appendStream from an open handle
  d.write("out.txt", "start|")
  src = syncio.open(root / "src.bin", fmRead)
  d.appendStream("out.txt", src)
  src.close()
  check d.read("out.txt") == "start|streamed data"

  if dirExists(root):
    removeDir(root)

test "size, lastModified, checksum, mimeType, metadata":
  let root = joinPath(getCurrentDir() / "tests" / "tmp_flysystem_test_meta")
  if dirExists(root):
    removeDir(root)
  createDir(root)

  let d = newLocalDriver(root)
  d.write("hello.txt", "hello world")
  check d.size("hello.txt") == 11
  check d.checksum("hello.txt") == getMD5("hello world")
  check d.mimeType("hello.txt") == "text/plain"
  check d.mimeType("noext") == "application/octet-stream"

  let before = getTime()
  d.write("stamp.txt", "x")
  check d.lastModified("stamp.txt") >= before

  # metadata returns root-relative path
  d.makeDir("nested")
  d.write("nested/deep.txt", "y")
  let m = d.metadata("nested/deep.txt")
  check m.path == "nested/deep.txt"
  check m.size == 1
  check not m.isDir

  # nonexistent file raises StorageError (not raw IOError)
  try:
    discard d.read("missing.txt")
    assert false, "Expected StorageError for missing file"
  except StorageError as e:
    check "missing.txt" in e.msg

  if dirExists(root):
    removeDir(root)

test "touch, readLines, deleteDir(force)":
  let root = joinPath(getCurrentDir() / "tests" / "tmp_flysystem_test_utils")
  if dirExists(root):
    removeDir(root)
  createDir(root)

  let d = newLocalDriver(root)

  # touch creates empty file
  d.touch("empty.txt")
  check d.exists("empty.txt")
  check d.size("empty.txt") == 0

  # readLines via memfiles
  d.write("lines.txt", "alpha\nbeta\r\ngamma\n")
  var lines: seq[string]
  for line in d.readLines("lines.txt"):
    lines.add line
  check lines == @["alpha", "beta", "gamma"]

  # readLines buffer reuse contract: copy lines out as you go
  var kept: seq[string]
  for line in d.readLines("lines.txt"):
    kept.add line
  check kept == @["alpha", "beta", "gamma"]

  # last line without trailing newline is still yielded
  d.write("notrail.txt", "only one line")
  var notrail: seq[string]
  for line in d.readLines("notrail.txt"):
    notrail.add line
  check notrail == @["only one line"]

  # empty file yields nothing
  d.write("empty.txt", "")
  var emptyCount = 0
  for _ in d.readLines("empty.txt"):
    inc emptyCount
  check emptyCount == 0

  # deleteDir without force fails on non-empty
  d.makeDir("populated")
  d.write("populated/f.txt", "x")
  try:
    d.deleteDir("populated")
    assert false, "Expected StorageError for non-empty dir"
  except StorageError as e:
    check "not empty" in e.msg
  check d.exists("populated")

  # deleteDir with force removes recursively
  d.deleteDir("populated", force = true)
  check not d.exists("populated")

  # deleteDir on empty dir without force works
  d.makeDir("empty")
  d.deleteDir("empty")
  check not d.exists("empty")

  if dirExists(root):
    removeDir(root)

test "copyDir, moveDir, search":
  let root = joinPath(getCurrentDir() / "tests" / "tmp_flysystem_test_dirs")
  if dirExists(root):
    removeDir(root)
  createDir(root)

  let d = newLocalDriver(root)
  d.write("src/nested/a.txt", "a")
  d.write("src/b.log", "b")

  # copyDir
  d.copyDir("src", "dst")
  check d.exists("dst/nested/a.txt")
  check d.exists("dst/b.log")
  check d.read("dst/nested/a.txt") == "a"

  # copyDir preserves empty directories
  d.makeDir("src/empty")
  d.copyDir("src", "dst2")
  check dirExists(root / "dst2/empty")
  check dirExists(root / "dst2/nested")

  # moveDir
  d.moveDir("dst", "moved")
  check d.exists("moved/nested/a.txt")
  check not d.exists("dst")

  # search with globs
  let logs = d.search("src/*.log")
  check logs == @["src/b.log"]
  let nested = d.search("src/nested/*.txt")
  check nested == @["src/nested/a.txt"]

  if dirExists(root):
    removeDir(root)

test "symlinks, withLock, chmod, diskUsage":
  let root = joinPath(getCurrentDir() / "tests" / "tmp_flysystem_test_adv")
  if dirExists(root):
    removeDir(root)
  createDir(root)

  let d = newLocalDriver(root)
  d.write("real.txt", "payload")

  # symlinks
  d.createSymlink("alias.txt", "real.txt")
  check d.isSymlink("alias.txt")
  check not d.isSymlink("real.txt")
  check d.readLink("alias.txt") == "real.txt"

  # withLock
  d.withLock("locked.txt"):
    d.append("locked.txt", "in lock")
  check d.read("locked.txt") == "in lock"

  # withLock must not truncate existing content
  d.write("count.txt", "41")
  d.withLock("count.txt"):
    let n = parseInt(d.read("count.txt"))
    d.write("count.txt", $(n + 1))
  check d.read("count.txt") == "42"

  # chmod
  d.chmod("real.txt", 0o600)
  check d.visibility("real.txt") == visPrivate
  d.chmod("real.txt", 0o644)
  check d.visibility("real.txt") == visPublic

  # chown to the current user/group
  when defined(posix):
    d.chown("real.txt", getuid().int, getgid().int)

  # diskUsage
  when defined(posix):
    let du = d.diskUsage()
    check du.total > 0
    check du.used >= 0
    check du.free > 0

  if dirExists(root):
    removeDir(root)

test "readStream, delete, list (non-recursive), error wrapping":
  let root = joinPath(getCurrentDir() / "tests" / "tmp_flysystem_test_more")
  if dirExists(root):
    removeDir(root)
  createDir(root)

  let d = newLocalDriver(root)

  # readStream returns a memory-mapped view of the file
  # (or a FileStream with -d:features.flysystem.useStdStreams)
  d.write("data.txt", "mapped content")
  when defined(features.flysystem.useStdStreams):
    var s = d.readStream("data.txt")
    check s.readAll() == "mapped content"
    s.close()
  else:
    var mf = d.readStream("data.txt")
    check mf.size == "mapped content".len
    var buf = newString(mf.size)
    copyMem(addr buf[0], mf.mem, mf.size)
    check buf == "mapped content"
    close(mf)

  # readStream of an empty file yields a resource-free size-0 stream
  # (with std/streams the stream must still be closed)
  d.write("zerobytes.txt", "")
  when defined(features.flysystem.useStdStreams):
    var zs = d.readStream("zerobytes.txt")
    check zs.readAll() == ""
    zs.close()
  else:
    let zmf = d.readStream("zerobytes.txt")
    check zmf.size == 0

  # delete removes a file
  d.write("garbage.txt", "x")
  check d.exists("garbage.txt")
  d.delete("garbage.txt")
  check not d.exists("garbage.txt")

  # list non-recursive only lists direct children
  d.write("root1.txt", "1")
  d.write("root2.txt", "2")
  d.makeDir("inner")
  d.write("inner/deep.txt", "3")
  let items = d.list("")
  var rootFiles = 0
  var sawDeep = false
  for it in items:
    if it.path == "root1.txt" or it.path == "root2.txt":
      inc rootFiles
    if it.path == "inner/deep.txt":
      sawDeep = true
  check rootFiles == 2
  check not sawDeep

  # missing-file operations raise StorageError (not raw IOError)
  for op in [proc(): string = (discard d.size("nope.txt"); ""),
             proc(): string = (discard d.metadata("nope.txt"); "")]:
    try:
      discard op()
      assert false, "Expected StorageError for missing file"
    except StorageError as e:
      check "nope.txt" in e.msg

  # delete of a missing file is an idempotent no-op
  d.delete("nope.txt")

  # readStream on a missing file raises StorageError too
  try:
    when defined(features.flysystem.useStdStreams):
      var bad = d.readStream("nope.txt")
      bad.close()
    else:
      var bad = d.readStream("nope.txt")
      close(bad)
    assert false, "Expected StorageError for missing file"
  except StorageError as e:
    check "nope.txt" in e.msg

  if dirExists(root):
    removeDir(root)