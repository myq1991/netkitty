# Change Log

All notable changes to this project will be documented in this file.
See [Conventional Commits](https://conventionalcommits.org) for commit guidelines.

# [1.2.0](https://github.com/myq1991/netkitty/compare/@netkitty/capture@1.1.0...@netkitty/capture@1.2.0) (2026-07-23)


### Features

* **capture:** map native host-process errors to NetKittyError subclasses ([9784273](https://github.com/myq1991/netkitty/commit/9784273701b84adefd3525c05755ce3eeadf7170))
* **errors:** add @netkitty/errors — shared NetKittyError base + ErrorCode ([d5a3405](https://github.com/myq1991/netkitty/commit/d5a3405ee1f812ac92ed3d32478c1bece9bdbd89))
* **errors:** route pcap-core/pcap/analysis/replay/capture errors through NetKittyError ([19b0888](https://github.com/myq1991/netkitty/commit/19b08886f490afaeec3620745e545eb2446b4f83))





# 1.1.0 (2026-07-22)


### Bug Fixes

* **capture:** electron 改为惰性加载,普通 Node 环境不再因静态导入崩溃 ([88c0f58](https://github.com/myq1991/netkitty/commit/88c0f58ddfb751a8541a470a7601776fbba80d65))
* **capture:** posix 抓包句柄设为非阻塞,修复连续流量下事件循环挂死 ([1a11b70](https://github.com/myq1991/netkitty/commit/1a11b70910b5c89272933ee7743f729ecafb4285))
* **capture:** 修复 Windows 链接——系统库改用 -l 前缀,并加 /utf-8 ([7a49e17](https://github.com/myq1991/netkitty/commit/7a49e1724bd0e053d05e376f79aafb6a92265044))
* **capture:** 修复原生插件多处 C++ 缺陷 ([a67d2fd](https://github.com/myq1991/netkitty/commit/a67d2fde251e98428ce96692067ddb42c2bf47b7))


### Features

* **capture:** P1a emit 配置 —— metadata 模式跳过每包 base64/字节 IPC ([3e9db36](https://github.com/myq1991/netkitty/commit/3e9db36a6d6947f5daac45a78e4331bae08d8662))
* **capture:** P3 宿主进程模型 —— N 个 worker 进程收敛为 1 个共享宿主 + 崩溃监督 ([6b78bec](https://github.com/myq1991/netkitty/commit/6b78bec4cb909516c44a0cd34e3fad6b87e5be6c))
* **monorepo:** 阶段2b 迁移 @netkitty/capture(native cpp 包) ([12caa2c](https://github.com/myq1991/netkitty/commit/12caa2c30e4a950213fde2beaac8786fd395bfe0))





# Changelog

All notable changes to this package are documented here, following
[Semantic Versioning](https://semver.org/). From the next release onward, entries
are generated automatically from Conventional Commits.

## 1.0.0 - 2026-07-22

First stable release.

- Live packet capture over libpcap/Npcap via a native addon, built from source
  on install (no prebuilt binaries).
- Verified end to end on macOS, Linux (glibc + musl) and Windows Server 2022.
