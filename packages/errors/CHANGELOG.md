# Changelog

All notable changes to this package are documented here, following
[Semantic Versioning](https://semver.org/). From the next release onward, entries
are generated automatically from Conventional Commits.

## 1.1.0 - 2026-07-23

First release.

- `NetKittyError` base class — extends the native `Error`, is `NodeJS.ErrnoException`-compatible
  (`errno` + `code`), and sets `name` to the concrete subclass. Every netkitty package's error extends it
  so callers can catch them uniformly via `instanceof NetKittyError`.
- `ErrorCode` — central error-code registry pairing each `errno` with a stable `code`, grouped by package
  (1000s capture, 2000s codec).
