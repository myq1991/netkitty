# Change Log

All notable changes to this project will be documented in this file.
See [Conventional Commits](https://conventionalcommits.org) for commit guidelines.

# [1.2.0](https://github.com/myq1991/netkitty/compare/@netkitty/analysis@1.1.0...@netkitty/analysis@1.2.0) (2026-07-23)


### Features

* **errors:** route pcap-core/pcap/analysis/replay/capture errors through NetKittyError ([19b0888](https://github.com/myq1991/netkitty/commit/19b08886f490afaeec3620745e545eb2446b4f83))





# 1.1.0 (2026-07-22)


### Bug Fixes

* **analysis:** 惰性 require 改用行内 eslint-disable,与 GetBinding 既有写法一致 ([a508355](https://github.com/myq1991/netkitty/commit/a50835510780ef216558b09be08c542b950e71fd))
* **analysis:** 消除 ESLint 报错(合并重复导入;关闭与 no-var-requires 一致的 no-require-imports) ([b1707d3](https://github.com/myq1991/netkitty/commit/b1707d3329496a80139c873b3a9d7ecc1f1ba552))


### Features

* **analysis:** 流式化 v1 步骤1 接口骨架 ([982c4a0](https://github.com/myq1991/netkitty/commit/982c4a074a0f48cff94138f47d1f70cfcad1276c))
* **analysis:** 流式化 v1 步骤10a 浏览器读后端 BrowserFileReadBackend ([333d84a](https://github.com/myq1991/netkitty/commit/333d84a478a302127a5ff9fd5b7e10606377af89))
* **analysis:** 流式化 v1 步骤10b-2 浏览器 worker 通道与门面 source 透传 ([a9ce915](https://github.com/myq1991/netkitty/commit/a9ce915741476050582b4ffbd9585ad906909355))
* **analysis:** 流式化 v1 步骤2 node 读后端 IReadBackend ([1398158](https://github.com/myq1991/netkitty/commit/13981586df05cec7be04c9c5848b498a6c6edf5a))
* **analysis:** 流式化 v1 步骤3 列式帧索引 ColumnarIndexStore ([cf6695f](https://github.com/myq1991/netkitty/commit/cf6695f64aeeb1f474e45aea5bdb6d39b70c37a5))
* **analysis:** 流式化 v1 步骤4a-1 五元组抽取与帧索引器 ([ed752f6](https://github.com/myq1991/netkitty/commit/ed752f64b32491bdc30d6127fff4dc26d1cf46be))
* **analysis:** 流式化 v1 步骤4a-2 端到端索引管线 PcapIndexBuilder ([b7e8ba1](https://github.com/myq1991/netkitty/commit/b7e8ba16829ae25d584f534458e40b36e39566d6))
* **analysis:** 流式化 v1 步骤4b 工作线程通道 IWorkerChannel ([7f399d0](https://github.com/myq1991/netkitty/commit/7f399d058165aed2932d3373a11185d55804fc78))
* **analysis:** 流式化 v1 步骤5 Analysis 门面串联与 open 端到端 ([375b6e9](https://github.com/myq1991/netkitty/commit/375b6e933183671e7c7ddde4050eb0ab195efbd4))
* **analysis:** 流式化 v1 步骤6a 内置 Conversations/Endpoints reducer ([db6928a](https://github.com/myq1991/netkitty/commit/db6928a0f49a398bc87542e9802336ba9bc00c38))
* **analysis:** 流式化 v1 步骤6b attachReducer 回放端到端 ([e6ac715](https://github.com/myq1991/netkitty/commit/e6ac7156978d23a1332b8819582fe21b19e964fe))
* **analysis:** 流式化 v1 步骤7 用户 reducer 路径细化 ([ef53161](https://github.com/myq1991/netkitty/commit/ef53161c0450d447488fd7ea97813472f7a5d7bf))
* **analysis:** 流式化 v1 步骤8a 内置 TcpStreamReducer ([8948c7b](https://github.com/myq1991/netkitty/commit/8948c7b928708c14fe2318874a625cf6f54a13cc))
* **analysis:** 流式化 v1 步骤8b watch tail 实时索引与内存治理 ([3b23864](https://github.com/myq1991/netkitty/commit/3b23864d920cf3615d7ca23de02570c7d376f8fb))
* **analysis:** 流式化 v1 步骤9 显示过滤器 filter ([25c5732](https://github.com/myq1991/netkitty/commit/25c573249c2dfe1a76970c7d72fc591b9d515adc))
* **monorepo:** 阶段1c 迁移 @netkitty/analysis ([b880b95](https://github.com/myq1991/netkitty/commit/b880b95c44b96f5cd34ad0078e050edcf7894a85))


### Performance Improvements

* **analysis:** filter 列粗筛（无方向谓词零重解码，全表 filter 提速约 415×） ([8686f87](https://github.com/myq1991/netkitty/commit/8686f879273befa600b37095997c23bf8956f468))
* **analysis:** P0 回放走列——indexOnly reducer 从索引列合成帧、跳过重解码（13×） ([0b19066](https://github.com/myq1991/netkitty/commit/0b190661204f01b06d84c9b2d5fe97668c15ab64))
* **analysis:** 内置 Conversations/Endpoints 移入 worker 扫索引列（主线程零负担） ([ea7521a](https://github.com/myq1991/netkitty/commit/ea7521adf19dadf1e2ce21a486a753ecf7bf3214))
* **analysis:** 索引加方向位，方向敏感 filter 也走列扫（ip.src 7240ms→26ms 约278×） ([649f0bb](https://github.com/myq1991/netkitty/commit/649f0bbfff18f6f596d218f3eb37935bf9fbf5cb))





# Changelog

All notable changes to this package are documented here, following
[Semantic Versioning](https://semver.org/). From the next release onward, entries
are generated automatically from Conventional Commits.

## 1.0.0 - 2026-07-22

First stable release.

- Streaming, Wireshark-style cross-packet analysis over a capture file
  (conversations, endpoints, TCP streams) running off a worker.
