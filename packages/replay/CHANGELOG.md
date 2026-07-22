# Changelog

All notable changes to this package are documented here, following
[Semantic Versioning](https://semver.org/). From the next release onward, entries
are generated automatically from Conventional Commits.

## 1.0.0 - 2026-07-22

First stable release.

- Replay captures at recorded inter-frame timing (or topspeed/mbps/pps) on a
  dedicated native thread that never blocks the Node event loop; also generate
  traffic. Native addon, built from source on install.
