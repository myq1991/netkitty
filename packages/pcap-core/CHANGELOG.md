# Change Log

All notable changes to this project will be documented in this file.
See [Conventional Commits](https://conventionalcommits.org) for commit guidelines.

# 1.1.0 (2026-07-22)


### Bug Fixes

* **pcap-core:** point index re-export at renamed PcapGenerator file ([8d366a3](https://github.com/myq1991/netkitty/commit/8d366a383e4111381c2081d17d08b589f87a3a56))


### Features

* **monorepo:** 阶段1b/2a 剥离 @netkitty/pcap-core(浏览器安全)+ @netkitty/pcap(node) ([4031746](https://github.com/myq1991/netkitty/commit/4031746079499212700facc16168049c56585488))
* **pcap-core:** 暴露纳秒级时间戳 nanoseconds ([2c61beb](https://github.com/myq1991/netkitty/commit/2c61beb509260ac3a6fa7f41d2eeb6176f913101))
* **pcap:** generate pcapng, and let PcapWriter emit it ([2d2ec4b](https://github.com/myq1991/netkitty/commit/2d2ec4bc30eb80721baf89b207f38aa69cef2606))
* **pcap:** transparent gzip and LZ4 decompression of capture files ([8440498](https://github.com/myq1991/netkitty/commit/844049830791b621b6414974c303bc1b61e81b02))





# Changelog

All notable changes to this package are documented here, following
[Semantic Versioning](https://semver.org/). From the next release onward, entries
are generated automatically from Conventional Commits.

## 1.0.0 - 2026-07-22

First stable release.

- Pure-buffer pcap/pcapng parsing and generation with no Node dependencies
  (browser-safe).
- Classic pcap generators (all four endian/precision variants) and a pcapng
  generator, plus a pure-JS LZ4 frame decompressor.
