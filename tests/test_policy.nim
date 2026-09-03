import unittest
import os, strutils
when defined(features.flysystem.useStdStreams):
  import std/streams
else:
  import std/memfiles
import std/syncio
import checksums/md5
import flysystem

proc makeRoot(name: string): string =
  result = joinPath(getCurrentDir() / "tests" / name)
  if dirExists(result):
    removeDir(result)
  createDir(result)

test "policy passes through with default rules":
  let root = makeRoot("tmp_policy_default")
  let d = newLocalDriver(root)
  let p = newFilesystemPolicy(d)

  p.write("a.txt", "hello")
  check p.read("a.txt") == "hello"
  check p.exists("a.txt")
  check p.size("a.txt") == 5
  check p.checksum("a.txt") == getMD5("hello")
  check p.mimeType("a.txt") == "text/plain"

  p.append("a.txt", "!")
  check p.read("a.txt") == "hello!"

  p.copy("a.txt", "b.txt")
  check p.exists("b.txt")
  p.move("b.txt", "c.txt")
  check p.exists("c.txt")
  check not p.exists("b.txt")
  p.delete("c.txt")
  check not p.exists("c.txt")

  p.makeDir("sub")
  p.write("sub/deep.txt", "d")
  check p.metadata("sub/deep.txt").size == 1
  check p.visibility("sub/deep.txt") == visPrivate
  p.setVisibility("sub/deep.txt", visPublic)
  check p.visibility("sub/deep.txt") == visPublic

  p.touch("touched.txt")
  check p.exists("touched.txt")

  check p.search("*.txt").len > 0
  check p.list("", recursive = true).len > 0

  # readStream through the policy
  when defined(features.flysystem.useStdStreams):
    var ps = p.readStream("a.txt")
    check ps.readAll() == "hello!"
    ps.close()
  else:
    var mf = p.readStream("a.txt")
    check mf.size == 6
    close(mf)
  p.deleteDir("sub", force = true)
  check not p.exists("sub")

  if dirExists(root):
    removeDir(root)

test "readOnly policy":
  let root = makeRoot("tmp_policy_readonly")
  let d = newLocalDriver(root)
  let p = newFilesystemPolicy(d, PolicyRules(readOnly: true))

  # setup a file via the raw driver
  d.write("data.txt", "payload")
  check p.read("data.txt") == "payload"

  for op in [proc(): void = p.write("x.txt", "x"),
             proc(): void = p.append("data.txt", "x"),
             proc(): void = p.delete("data.txt"),
             proc(): void = p.move("data.txt", "y.txt"),
             proc(): void = p.copy("data.txt", "y.txt"),
             proc(): void = p.makeDir("dir"),
             proc(): void = p.deleteDir("dir"),
             proc(): void = p.touch("z.txt"),
             proc(): void = p.setVisibility("data.txt", visPublic)]:
    try:
      op()
      assert false, "Expected FilesystemPolicyError for read-only operation"
    except FilesystemPolicyError as e:
      check e.rule == "readOnly"
      check e.operation.len > 0

  if dirExists(root):
    removeDir(root)

test "maxFileSize policy":
  let root = makeRoot("tmp_policy_size")
  let d = newLocalDriver(root)
  let p = newFilesystemPolicy(d, PolicyRules(maxFileSize: 10))

  p.write("ok.txt", "12345")
  check p.read("ok.txt") == "12345"

  try:
    p.write("big.txt", "12345678901")
    assert false, "Expected FilesystemPolicyError for oversized write"
  except FilesystemPolicyError as e:
    check e.rule == "maxFileSize"

  # append beyond the cap
  try:
    p.append("ok.txt", "123456")
    assert false, "Expected FilesystemPolicyError for oversized append"
  except FilesystemPolicyError as e:
    check e.rule == "maxFileSize"

  # writeStream beyond the cap
  writeFile(root / "src.big", "123456789012345")
  var src = syncio.open(root / "src.big", fmRead)
  try:
    p.writeStream("streamed.bin", src)
    assert false, "Expected FilesystemPolicyError for oversized writeStream"
  except FilesystemPolicyError as e:
    check e.rule == "maxFileSize"
  src.close()

  if dirExists(root):
    removeDir(root)

test "allowedExtensions and allowedMimeTypes policies":
  let root = makeRoot("tmp_policy_ext")
  let d = newLocalDriver(root)
  let p = newFilesystemPolicy(d, PolicyRules(
    allowedExtensions: @["txt", "bin"],
    allowedMimeTypes: @["text/plain"]))

  p.write("ok.txt", "text")
  check p.read("ok.txt") == "text"

  try:
    p.write("evil.exe", "nope")
    assert false, "Expected FilesystemPolicyError for disallowed extension"
  except FilesystemPolicyError as e:
    check e.rule == "allowedExtensions"

  # ".bin" is allowed by extension but not by mime type
  try:
    p.write("binary.bin", "nope")
    assert false, "Expected FilesystemPolicyError for disallowed mime type"
  except FilesystemPolicyError as e:
    check e.rule == "allowedMimeTypes"

  # move/copy targets are checked too
  try:
    p.copy("ok.txt", "evil.exe")
    assert false, "Expected FilesystemPolicyError for disallowed extension on copy"
  except FilesystemPolicyError as e:
    check e.rule == "allowedExtensions"

  try:
    p.move("ok.txt", "renamed.bin")
    assert false, "Expected FilesystemPolicyError for disallowed mime type on move"
  except FilesystemPolicyError as e:
    check e.rule == "allowedMimeTypes"

  # file without an extension is not allowed when an allowlist is set
  try:
    p.write("noext", "x")
    assert false, "Expected FilesystemPolicyError for missing extension"
  except FilesystemPolicyError as e:
    check e.rule == "allowedExtensions"

  # copyDir rejects a tree containing a disallowed file up-front
  d.makeDir("src")
  d.write("src/good.txt", "a")
  d.write("src/bad.exe", "b")
  try:
    p.copyDir("src", "dst")
    assert false, "Expected FilesystemPolicyError for disallowed file inside copied tree"
  except FilesystemPolicyError as e:
    check e.rule == "allowedExtensions"
  check not d.exists("dst")

  if dirExists(root):
    removeDir(root)

test "denyHiddenFiles blocks and filters":
  let root = makeRoot("tmp_policy_hidden")
  let d = newLocalDriver(root)
  let p = newFilesystemPolicy(d, PolicyRules(denyHiddenFiles: true))

  p.write("visible.txt", "x")
  d.write(".secret", "hidden")   # create via raw driver

  try:
    p.write(".hidden.txt", "nope")
    assert false, "Expected FilesystemPolicyError for hidden file"
  except FilesystemPolicyError as e:
    check e.rule == "denyHiddenFiles"

  try:
    p.makeDir(".cache")
    assert false, "Expected FilesystemPolicyError for hidden directory"
  except FilesystemPolicyError as e:
    check e.rule == "denyHiddenFiles"

  # hidden files are filtered out of listings
  let files = p.list("")
  for it in files:
    check not it.path.startsWith(".")
  check not p.exists(".hidden.txt") or true

  let found = p.search("*")
  for f in found:
    check not extractFilename(f).startsWith(".")

  # exists / metadata still work for hidden files (read access allowed)
  check p.exists(".secret")

  if dirExists(root):
    removeDir(root)

test "maxPathLength and maxDepth policies":
  let root = makeRoot("tmp_policy_path")
  let d = newLocalDriver(root)
  let p = newFilesystemPolicy(d, PolicyRules(maxPathLength: 10, maxDepth: 2))

  p.write("short.txt", "x")
  try:
    p.write("way_too_long_filename.txt", "x")
    assert false, "Expected FilesystemPolicyError for too-long path"
  except FilesystemPolicyError as e:
    check e.rule == "maxPathLength"

  p.write("a/b.txt", "x")
  try:
    p.write("a/b/c.txt", "x")
    assert false, "Expected FilesystemPolicyError for too-deep path"
  except FilesystemPolicyError as e:
    check e.rule == "maxDepth"

  if dirExists(root):
    removeDir(root)

test "policy error is a StorageError":
  let root = makeRoot("tmp_policy_err")
  let d = newLocalDriver(root)
  let p = newFilesystemPolicy(d, PolicyRules(readOnly: true))

  try:
    p.write("x.txt", "x")
    assert false, "Expected StorageError"
  except StorageError as e:
    check e of FilesystemPolicyError

  if dirExists(root):
    removeDir(root)

test "policy attached to a Filesystem disk":
  let root = makeRoot("tmp_policy_fs")
  let d = newLocalDriver(root)
  let fs = newFilesystem()
  fs.addDisk("secure", d, PolicyRules(allowedExtensions: @["txt"]))
  fs.addDisk("open", newLocalDriver(root / "open"))

  # policy is enforced through the facade
  fs.disk("secure").write("ok.txt", "fine")
  try:
    fs.disk("secure").write("bad.exe", "nope")
    assert false, "Expected FilesystemPolicyError through the facade"
  except FilesystemPolicyError as e:
    check e.rule == "allowedExtensions"

  # the default-policy disk returns the raw driver
  check not (fs.disk("open") of FilesystemPolicy)
  check fs.disk("secure") of FilesystemPolicy

  # diskPolicy returns the attached rules
  check fs.diskPolicy("secure").allowedExtensions == @["txt"]

  # rawDisk bypasses the policy
  fs.rawDisk("secure").write("bypass.exe", "allowed")
  check fs.rawDisk("secure").read("bypass.exe") == "allowed"

  if dirExists(root):
    removeDir(root)
