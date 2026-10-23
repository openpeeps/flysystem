import unittest
import os, strutils, times, posix
import std/[asyncdispatch, syncio]
import checksums/md5
import flysystem
import flysystem/local_async

proc makeRoot(name: string): string =
  result = joinPath(getCurrentDir() / "tests" / name)
  if dirExists(result):
    removeDir(result)
  createDir(result)

test "async write/read/exists/delete":
  let root = makeRoot("tmp_async_basic")
  let d = newAsyncLocalDriver(root)
  proc main() {.async.} =
    check not (await d.exists("a.txt"))
    await d.write("a.txt", "hello async")
    check await d.exists("a.txt")
    check (await d.read("a.txt")) == "hello async"
    await d.delete("a.txt")
    check not (await d.exists("a.txt"))
  waitFor main()
  if dirExists(root):
    removeDir(root)

test "async metadata/size/lastModified/checksum/mimeType":
  let root = makeRoot("tmp_async_meta")
  let d = newAsyncLocalDriver(root)
  proc main() {.async.} =
    await d.write("hello.txt", "hello world")
    check (await d.size("hello.txt")) == 11
    check (await d.checksum("hello.txt")) == getMD5("hello world")
    check (await d.mimeType("hello.txt")) == "text/plain"
    let m = await d.metadata("hello.txt")
    check m.path == "hello.txt"
    check m.size == 11
    check not m.isDir
    let before = getTime() - initDuration(milliseconds = 50)
    await d.write("stamp.txt", "x")
    check (await d.lastModified("stamp.txt")) >= before
    # missing file raises StorageError
    try:
      discard await d.read("missing.txt")
      assert false, "Expected StorageError for missing file"
    except StorageError as e:
      check "missing.txt" in e.msg
  waitFor main()
  if dirExists(root):
    removeDir(root)

test "async append and streams":
  let root = makeRoot("tmp_async_stream")
  let d = newAsyncLocalDriver(root)
  proc main() {.async.} =
    await d.append("log.txt", "line1\n")
    await d.append("log.txt", "line2\n")
    check (await d.read("log.txt")) == "line1\nline2\n"
    writeFile(root / "src.bin", "streamed data")
    var src = syncio.open(root / "src.bin", fmRead)
    await d.writeStream("dst.bin", src)
    src.close()
    check (await d.read("dst.bin")) == "streamed data"
    check (await d.readStream("dst.bin")) == "streamed data"
    # appendStream from an open handle
    await d.write("out.txt", "start|")
    src = syncio.open(root / "src.bin", fmRead)
    await d.appendStream("out.txt", src)
    src.close()
    check (await d.read("out.txt")) == "start|streamed data"
    # append on existing content via async append
    await d.append("out.txt", "|tail")
    check (await d.read("out.txt")) == "start|streamed data|tail"
    # touch creates an empty file without truncating existing ones
    await d.touch("empty.txt")
    check await d.exists("empty.txt")
    check (await d.size("empty.txt")) == 0
    await d.touch("out.txt")
    check (await d.read("out.txt")) == "start|streamed data|tail"
  waitFor main()
  if dirExists(root):
    removeDir(root)

test "async dirs, move/copy, search, readLines":
  let root = makeRoot("tmp_async_dirs")
  let d = newAsyncLocalDriver(root)
  proc main() {.async.} =
    await d.write("src/nested/a.txt", "a")
    await d.write("src/b.log", "b")
    await d.copyDir("src", "dst")
    check await d.exists("dst/nested/a.txt")
    check (await d.read("dst/nested/a.txt")) == "a"
    await d.moveDir("dst", "moved")
    check await d.exists("moved/nested/a.txt")
    check not (await d.exists("dst"))
    check (await d.search("src/*.log")) == @["src/b.log"]
    await d.move("src/b.log", "src/c.log")
    check await d.exists("src/c.log")
    await d.copy("src/c.log", "src/d.log")
    check await d.exists("src/d.log")
    # readLines
    await d.write("lines.txt", "alpha\nbeta\r\ngamma\n")
    check (await d.readLines("lines.txt")) == @["alpha", "beta", "gamma"]
    # traversal is blocked
    try:
      await d.write("../evil.txt", "nope")
      assert false, "Expected StorageError for path traversal"
    except StorageError as e:
      check "Path traversal detected" in e.msg
  waitFor main()
  if dirExists(root):
    removeDir(root)

test "async visibility, touch, symlinks, posix":
  let root = makeRoot("tmp_async_adv")
  let d = newAsyncLocalDriver(root)
  proc main() {.async.} =
    await d.write("secret.txt", "top secret", visPrivate)
    check (await d.visibility("secret.txt")) == visPrivate
    await d.setVisibility("secret.txt", visPublic)
    check (await d.visibility("secret.txt")) == visPublic
    await d.touch("empty.txt")
    check await d.exists("empty.txt")
    await d.createSymlink("alias.txt", "secret.txt")
    check await d.isSymlink("alias.txt")
    check (await d.readLink("alias.txt")) == "secret.txt"
    when defined(posix):
      await d.chmod("secret.txt", 0o600)
      check (await d.visibility("secret.txt")) == visPrivate
      await d.chown("secret.txt", getuid().int, getgid().int)
      let du = await d.diskUsage()
      check du.total > 0
      check du.free > 0
    await d.makeDir("populated")
    await d.write("populated/f.txt", "x")
    try:
      await d.deleteDir("populated")
      assert false, "Expected StorageError for non-empty dir"
    except StorageError as e:
      check "not empty" in e.msg
    await d.deleteDir("populated", force = true)
    check not (await d.exists("populated"))
  waitFor main()
  if dirExists(root):
    removeDir(root)

test "async sandbox: prefix sibling and symlinks":
  let root = makeRoot("tmp_async_sandbox")
  let sibling = joinPath(getCurrentDir() / "tests" / "tmp_async_sandbox-backup")
  if dirExists(sibling): removeDir(sibling)
  createDir(sibling)
  writeFile(sibling / "secret.txt", "PREFIX-LEAK")
  let outside = joinPath(getCurrentDir() / "tests" / "tmp_async_outside.txt")
  writeFile(outside, "OUTSIDE-LEAK")
  let d = newAsyncLocalDriver(root)
  proc main() {.async.} =
    await d.write("real.txt", "payload")
    check (await d.read("real.txt")) == "payload"
    try:
      discard await d.read("../tmp_async_sandbox-backup/secret.txt")
      assert false, "Expected StorageError for prefix-sibling escape"
    except StorageError as e:
      check "Path traversal detected" in e.msg
    os.createSymlink("real.txt", root / "inward.txt")
    check (await d.read("inward.txt")) == "payload"
    os.createSymlink(outside, root / "escape.txt")
    try:
      discard await d.read("escape.txt")
      assert false, "Expected StorageError for outward symlink"
    except StorageError as e:
      check "Path traversal detected" in e.msg
    check await d.isSymlink("escape.txt")
    await d.delete("escape.txt")
    check not (await d.exists("escape.txt"))
    check readFile(outside) == "OUTSIDE-LEAK"
  waitFor main()
  removeFile(outside)
  if dirExists(sibling): removeDir(sibling)
  if dirExists(root): removeDir(root)
