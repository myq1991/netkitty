# Change Log

All notable changes to this project will be documented in this file.
See [Conventional Commits](https://conventionalcommits.org) for commit guidelines.

# 1.1.0 (2026-07-22)


### Features

* **iface:** 新增 @netkitty/iface —— 只读网卡枚举/地址/tx-rx 统计(原生) ([d556876](https://github.com/myq1991/netkitty/commit/d556876b4350083770481d253ff0a9c9a4134550))
* **monorepo:** 阶段3 聚合 netkitty 包 + subpath 兼容 + 根转 workspace root ([6eca06c](https://github.com/myq1991/netkitty/commit/6eca06c8d49148d3494abca74721d3ea65843e0b))
* **replay:** 新增 @netkitty/replay —— 数据包重放与流量生成(原生) ([9032279](https://github.com/myq1991/netkitty/commit/9032279e192afbc908992acfc8f9ab9c739a0467))





# Changelog

All notable changes to this package are documented here, following
[Semantic Versioning](https://semver.org/). From the next release onward, entries
are generated automatically from Conventional Commits.

## 1.0.0 - 2026-07-22

First stable release.

- Aggregate package re-exporting the whole toolkit by subpath: netkitty/codec,
  netkitty/pcap, netkitty/analysis, netkitty/network (capture), netkitty/iface,
  netkitty/replay and netkitty/helper.
