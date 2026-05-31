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
- **Rich Metadata**: Retrieve detailed file metadata, including size, last modified
- **Preventing Directory Traversal**: All file operations are securely sandboxed to prevent access outside the designated root directory, mitigating directory traversal vulnerabilities.
- **Memory-Efficient**: Designed to handle large files without loading them entirely into memory via MemFiles

## Examples
```nim
import flysystem

# todo
```

### ❤ Contributions & Support
- 🐛 Found a bug? [Create a new Issue](https://github.com/openpeeps/flysystem/issues)
- 👋 Wanna help? [Fork it!](https://github.com/openpeeps/flysystem/fork)
- 😎 [Get €20 in cloud credits from Hetzner](https://hetzner.cloud/?ref=Hm0mYGM9NxZ4)

### 🎩 License
MIT license. [Made by Humans from OpenPeeps](https://github.com/openpeeps).<br>
Copyright OpenPeeps & Contributors &mdash; All rights reserved.
