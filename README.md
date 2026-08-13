<p align="center">
  A filesystem API for Nim, inspired by Flysystem from the PHP ecosystem.
</p>

<p align="center">
  <code>nimble install flysystem</code>
</p>

<p align="center">
  <a href="https://openpeeps.github.io/flysystem">API reference</a><br>
  <img src="https://github.com/openpeeps/flysystem/workflows/test/badge.svg" alt="Github Actions">  <img src="https://github.com/openpeeps/flysystem/workflows/docs/badge.svg" alt="Github Actions">
</p>

## 😍 Key Features
- **Unified API**: A consistent interface for working with files across different storage backends (local, cloud, etc.).
- **Extensible Drivers**: Easily add support for new storage backends by implementing the `Driver` interface.
- **Rich Metadata**: Retrieve detailed file metadata, including size, last modified time, visibility, checksum and MIME type.
- **Preventing Directory Traversal**: All file operations are securely sandboxed to prevent access outside the designated root directory, mitigating directory traversal vulnerabilities.
- **Atomic Writes**: Content is written to a temporary file and renamed over the target, so a crash mid-write never corrupts a file.
- **Memory-Efficient**: Handle large files without loading them entirely into memory via `MemFiles`, including a zero-allocation `readLines` iterator.
- **POSIX Tooling**: Symlinks, advisory file locking, `chmod`/`chown` and `statvfs`-based disk-usage helpers.
- **Security Policies**: Wrap any driver with `FilesystemPolicy` to enforce read-only mode, size caps, extension/MIME allowlists, hidden-file denial and path limits — attachable per disk.
- **Multi-Disk Facade**: Group several drivers under a `Filesystem` and switch between them with one call.

> [!NOTE]
> Only the local filesystem driver is available today. The driver interface is ready for custom backends and cloud drivers are on the roadmap.

## 📖 Examples

### Quick start
```nim
import flysystem

# the root is resolved at runtime (env var, config key, ...)
let d = newLocalDriver(getCurrentDir() / "uploads")

d.write("hello.txt", "Hello, World!")
echo d.read("hello.txt")      # "Hello, World!"
echo d.exists("hello.txt")    # true
```

### Basic file operations
```nim
import flysystem

let d = newLocalDriver("/srv/storage")

# write / read
d.write("notes.txt", "buy milk")
echo d.read("notes.txt")      # "buy milk"

# move & copy
d.move("notes.txt", "archive/notes.txt")   # parent dirs are created
d.copy("archive/notes.txt", "notes.bak")

# delete
d.delete("notes.bak")
echo d.exists("notes.bak")    # false
```

### Directories
```nim
d.makeDir("assets/images")     # creates parent dirs too

d.copyDir("assets", "backup")  # recursive copy
d.moveDir("backup", "old")     # recursive move

# by default deleteDir refuses to remove non-empty directories
d.deleteDir("old")             # StorageError: Directory not empty
# pass force = true to remove recursively
d.deleteDir("old", force = true)

d.touch("empty.txt")           # create an empty file (or bump its mtime)
```

### Visibility & permissions
```nim
# writes are private (0o600) by default
d.write("secret.txt", "top secret")

# ...or explicitly public (0o644)
d.write("public.txt", "hi", visPublic)

echo d.visibility("secret.txt")   # visPrivate
d.setVisibility("secret.txt", visPublic)

# POSIX-only direct permission/owner control
d.chmod("secret.txt", 0o600)      # set permission bits
# chown requires an `import std/posix` and appropriate privileges
d.chown("secret.txt", getuid().int, getgid().int) # set uid / gid
```

### Metadata & information
```nim
let m = d.metadata("notes.txt")
echo m.path                        # "notes.txt" (root-relative)
echo m.size                        # 9
echo m.lastModified                # Time
echo m.isDir                       # false

echo d.size("notes.txt")           # 9 (int64)
echo d.lastModified("notes.txt")   # Time
echo d.checksum("notes.txt")       # "e194f103..." (md5 hex)
echo d.mimeType("notes.txt")       # "text/plain"

# list the contents of a directory (recursively or not)
for item in d.list("assets", recursive = true):
  echo item.path
```

### Appending & streaming
```nim
# append text
d.append("log.txt", "line1\n")
d.append("log.txt", "line2\n")

# stream the contents of an open file handle
var src = open("localfile.bin", fmRead)
d.writeStream("stored.bin", src)
src.close()

# append a stream to an existing file
src = open("localfile.bin", fmRead)
d.appendStream("log.bin", src)
src.close()

# read a file as a memory-mapped stream (great for large files)
var mf = d.readStream("stored.bin")
echo mf.size
defer: mf.close()
```

### Reading lines (zero-allocation)
```nim
# readLines memory-maps the file and reuses a single buffer, so no
# allocations happen per line. The yielded string is only valid until
# the next iteration — copy it if you need to keep it.
for line in d.readLines("huge.log"):
  if "error" in line:
    echo line
```

### Symlinks
```nim
d.createSymlink("latest.txt", "releases/v1.0.txt")  # target must stay in the root
echo d.isSymlink("latest.txt")   # true
echo d.readLink("latest.txt")    # "releases/v1.0.txt"
```

### Advisory locking
```nim
# run a block while holding an exclusive lock on a file (POSIX)
d.withLock("counter.txt"):
  # only one writer at a time
  let n = parseInt(d.read("counter.txt"))
  d.write("counter.txt", $(n + 1))
```

### Glob search
```nim
# returns paths relative to the root
echo d.search("*.png")          # @["icon.png", "logo.png"]
echo d.search("cache/*.log")    # @["cache/run.log"]
```

### Disk usage
```nim
let du = d.diskUsage()          # POSIX-only
echo "free: ", du.free, " bytes of ", du.total
```

### Multi-disk Filesystem facade
```nim
let fs = newFilesystem()
fs.addDisk("local", newLocalDriver("/tmp/local"))
fs.addDisk("cache", newLocalDriver("/tmp/cache"))

fs.write("hello.txt", "hi")              # default disk
echo fs.read("hello.txt")                # "hi"
echo fs.exists("hello.txt")              # true
fs.delete("hello.txt")

# switch disks on the fly
fs.disk("cache").write("cached.json", "{}")
echo fs.disk("cache").read("cached.json")
```

### Error handling & security
```nim
try:
  d.read("missing.txt")
except StorageError as e:
  echo e.msg   # "Failed to read 'missing.txt': ..."

# every driver is sandboxed: nothing can escape the root
try:
  d.write("../evil.txt", "nope")
except StorageError as e:
  echo e.msg   # "Path traversal detected: ../evil.txt"
```

### 🔒 Security policies
```nim
import flysystem

# a policy layer wraps any driver and rejects violating operations
# with a PolicyError (a subtype of StorageError)
let d = newLocalDriver("/srv/uploads")

let rules = PolicyRules(
  readOnly: false,                 # deny all mutating operations
  maxFileSize: 10 * 1024 * 1024,   # 10 MB per file (0 = unlimited)
  maxPathLength: 255,              # max path chars (0 = unlimited)
  maxDepth: 8,                     # max path segments (0 = unlimited)
  denyHiddenFiles: true,           # block ".foo" files and filter listings
  allowedExtensions: @["png", "jpg", "txt"],
  allowedMimeTypes: @["image/png", "image/jpeg", "text/plain"])

let secure = newFilesystemPolicy(d, rules)

try:
  secure.write("evil.exe", "...")  # blocked by allowedExtensions
except PolicyError as e:
  echo e.rule          # "allowedExtensions"
  echo e.operation     # "write"

# attach a policy to a disk on the Filesystem facade
let fs = newFilesystem()
fs.addDisk("uploads", d, rules)
fs.disk("uploads").write("photo.jpg", "...")   # ok
try:
  fs.disk("uploads").write("payload.bin", "...")  # blocked
except PolicyError as e:
  echo e.rule           # "allowedExtensions" (".bin" is not allowlisted)

# bypass the policy when you really need the raw driver
fs.rawDisk("uploads").write("internal.bin", "...")
```

## ❤ Contributions & Support
- 🐛 Found a bug? [Create a new Issue](https://github.com/openpeeps/flysystem/issues)
- 👋 Wanna help? [Fork it!](https://github.com/openpeeps/flysystem/fork)

## 🎩 License
MIT license. [Made by Humans from OpenPeeps](https://github.com/openpeeps).<br>
Copyright OpenPeeps & Contributors &mdash; All rights reserved.
