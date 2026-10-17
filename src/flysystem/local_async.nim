#
# Async Local Driver — platform dispatcher.
#
# (c) 2026 George Lemon | MIT License
#     Made by Humans from OpenPeeps
#     https://github.com/openpeeps/flysystem
#
# Same split as the sync driver: descriptor-walk on POSIX, lexical
# containment elsewhere (see `local.nim`).
#
when defined(posix):
  include local_async_secure_impl
else:
  include local_async_lexical_impl
