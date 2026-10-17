#
# Local Driver — platform dispatcher.
#
# (c) 2026 George Lemon | MIT License
#     Made by Humans from OpenPeeps
#     https://github.com/openpeeps/flysystem
#
# POSIX targets use the descriptor-walk implementation (`securejoin`):
# every operation descends from a held root fd via `openat`, so
# containment is enforced by construction. Non-POSIX targets (Windows)
# use the lexical implementation: `normalizedPath` plus a separator-
# boundary prefix check. Documented as weaker — it closes prefix confusion
# but cannot close symlink or TOCTOU holes without `openat`.
#
when defined(posix):
  include local_secure_impl
else:
  include local_lexical_impl
