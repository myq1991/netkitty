# Change Log

All notable changes to this project will be documented in this file.
See [Conventional Commits](https://conventionalcommits.org) for commit guidelines.

# 1.2.0 (2026-07-23)


### Features

* **capture:** map native host-process errors to NetKittyError subclasses ([9784273](https://github.com/myq1991/netkitty/commit/9784273701b84adefd3525c05755ce3eeadf7170))
* **errors:** add @netkitty/errors — shared NetKittyError base + ErrorCode ([d5a3405](https://github.com/myq1991/netkitty/commit/d5a3405ee1f812ac92ed3d32478c1bece9bdbd89))
* **errors:** route pcap-core/pcap/analysis/replay/capture errors through NetKittyError ([19b0888](https://github.com/myq1991/netkitty/commit/19b08886f490afaeec3620745e545eb2446b4f83))
* **replay:** wrap the native send-thread error as ReplaySendError ([dc84862](https://github.com/myq1991/netkitty/commit/dc848622f2a21e8c4825968a536e02f3ee55c827))





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
