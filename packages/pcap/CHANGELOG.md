# Changelog

All notable changes to this package are documented here, following
[Semantic Versioning](https://semver.org/). From the next release onward, entries
are generated automatically from Conventional Commits.

## 1.0.0 - 2026-07-22

First stable release.

- Node streaming read/write/parse of pcap, pcapng and .cap/tcpdump files, format
  auto-detected by magic number, with transparent gzip and LZ4 decompression.
- PcapWriter emits both pcap and pcapng; PcapEdit streams a capture through
  built-in transforms (rewrite/retime/patch) with progress callbacks.
