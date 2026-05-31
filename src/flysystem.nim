#
# A filesystem API for Nim, inspired by Flysystem
# from the PHP ecosystem.
# 
# (c) 2026 George Lemon | MIT License
#     Made by Humans from OpenPeeps
#     https://github.com/openpeeps/flysystem

## This module implements a flexible filesystem abstraction layer, allowing you to
## manage files across different storage backends (like local disk, cloud storage, etc.)
## using a consistent API.
## 
## The `Filesystem` type provides a multi-disk abstraction where you can define multiple "disks"
## (storage backends) and perform file operations on them using a unified interface.
## 
## The `StorageDriver` type is an abstract base for different storage implementations,
## and the `LocalDriver` is a concrete implementation that interacts with the local filesystem.
## 
## The `Visibility` enum defines file visibility options (public or private), which can be used to
## set permissions or access controls depending on the storage backend.

import ./flysystem/[core, local]
export core, local