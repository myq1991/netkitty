# Change Log

All notable changes to this project will be documented in this file.
See [Conventional Commits](https://conventionalcommits.org) for commit guidelines.

# [1.2.0](https://github.com/myq1991/netkitty/compare/@netkitty/pcap@1.1.0...@netkitty/pcap@1.2.0) (2026-07-23)


### Features

* **errors:** route pcap-core/pcap/analysis/replay/capture errors through NetKittyError ([19b0888](https://github.com/myq1991/netkitty/commit/19b08886f490afaeec3620745e545eb2446b4f83))





# 1.1.0 (2026-07-22)


### Features

* **capture:** P1a emit 配置 —— metadata 模式跳过每包 base64/字节 IPC ([3e9db36](https://github.com/myq1991/netkitty/commit/3e9db36a6d6947f5daac45a78e4331bae08d8662))
* **monorepo:** 阶段1b/2a 剥离 @netkitty/pcap-core(浏览器安全)+ @netkitty/pcap(node) ([4031746](https://github.com/myq1991/netkitty/commit/4031746079499212700facc16168049c56585488))
* **pcap-core:** 暴露纳秒级时间戳 nanoseconds ([2c61beb](https://github.com/myq1991/netkitty/commit/2c61beb509260ac3a6fa7f41d2eeb6176f913101))
* **pcap:** generate pcapng, and let PcapWriter emit it ([2d2ec4b](https://github.com/myq1991/netkitty/commit/2d2ec4bc30eb80721baf89b207f38aa69cef2606))
* **pcap:** PcapEdit — stream-based capture editing with built-in transforms ([6abe950](https://github.com/myq1991/netkitty/commit/6abe950b093c487f0ee8c094f909af9f6cf79235))
* **pcap:** PcapEdit.retime — windowed retiming with continuity, units, progress ([6fed40a](https://github.com/myq1991/netkitty/commit/6fed40a1cd94a27fff147909c50654d1f15d330c))
* **pcap:** transparent gzip and LZ4 decompression of capture files ([8440498](https://github.com/myq1991/netkitty/commit/844049830791b621b6414974c303bc1b61e81b02))





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
