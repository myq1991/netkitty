# Change Log

All notable changes to this project will be documented in this file.
See [Conventional Commits](https://conventionalcommits.org) for commit guidelines.

# 1.1.0 (2026-07-22)


### Features

* **replay:** 新增 @netkitty/replay —— 数据包重放与流量生成(原生) ([9032279](https://github.com/myq1991/netkitty/commit/9032279e192afbc908992acfc8f9ab9c739a0467))
* **replay:** 新增 TX_RING 高吞吐后端与可选 CPU 亲和性 ([60e3dc0](https://github.com/myq1991/netkitty/commit/60e3dc0399ee4f424c39ae94c980a1307c216b54))





# Changelog

All notable changes to this package are documented here, following
[Semantic Versioning](https://semver.org/). From the next release onward, entries
are generated automatically from Conventional Commits.

## 1.0.0 - 2026-07-22

First stable release.

- Replay captures at recorded inter-frame timing (or topspeed/mbps/pps) on a
  dedicated native thread that never blocks the Node event loop; also generate
  traffic. Native addon, built from source on install.
