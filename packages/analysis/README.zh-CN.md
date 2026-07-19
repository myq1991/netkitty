# @netkitty/analysis

抓包文件的流式跨包分析——一个可编程的、Wireshark 式的 pcap/pcapng 门面。同一个 `Analysis` 类
**在 node 与浏览器中通用**：重活（读取 → 解析 → 部分解码 → 列式索引 → 解码）都在单个 worker 里跑，
所以 `open()` 不阻塞调用者，`close()` 通过终止 worker 一次性释放全部内存。

> English docs: [README.md](./README.md).

底层依赖 [`@netkitty/codec`](../codec)（协议解码）与 [`@netkitty/pcap-core`](../pcap-core)
（pcap/pcapng 解析）——均为纯 buffer、浏览器安全。

## 安装

```bash
npm i @netkitty/analysis
# 或用聚合包：import ... from 'netkitty/analysis'
```

## 快速上手（node）

```ts
import {Analysis, ConversationsReducer} from '@netkitty/analysis'

const analysis = new Analysis()
await analysis.open('/path/to/capture.pcap')      // 有界文件：建索引，完成后触发 'complete'

analysis.frameCount()                              // 已索引的总帧数
const rows = await analysis.getFrames(0, 100)      // 轻量行（不含解码 layers）
const frame = await analysis.getFrame(42)          // 单帧，含解码 layers
const tcp = await analysis.filter('tcp')           // 命中帧号

const conversations = new ConversationsReducer()
await analysis.attachReducer(conversations)        // 先回放所有已索引帧，再跟随实时流
conversations.result()                             // 随时快照（无 finalize）

await analysis.close()                             // 终止 worker，释放全部
```

## Reducer

Reducer 是可插拔的滚动分析，逐帧喂入；`result()` 随时返回快照（没有 finalize）。`attachReducer`
会先**回放**全部已索引帧，再跟随实时流——所以 attach 返回时统计即已完整（“打开即出统计”）。

- **内置**（已导出，自行 attach）：`ConversationsReducer`、`EndpointsReducer`、`TcpStreamReducer`
  （重传 / 重复 ACK / RTT）。
- **便利工厂**：`reduceReducer(seed, fold)`、`groupByReducer(keyOf, seed, fold)`。
- **自定义**：实现 `IAnalysisReducer<T>`（`update(frame, ctx)` / `result()` / `reset()`）；声明
  `needs: string[]` 只接收这些协议层（worker 只投影它们，减少跨线程数据）。

```ts
import {reduceReducer, groupByReducer} from '@netkitty/analysis'

const totalBytes = reduceReducer(0, (sum, frame) => sum + frame.length)
const perProtocol = groupByReducer(f => f.topProtocol, 0, count => count + 1)
```

## 实时抓包（watch）

`watch()` 会 tail 一个持续增长的抓包文件，以 phase `'live'` 逐帧喂 reducer。索引**默认无界**
（内存由你自负）。`maxFrames` 是可选的内存护栏：超过上限时对最老的索引条目做 FIFO 驱逐
（Wireshark 式环形缓冲），让长跑的 tail 内存有界——只丢内存里的索引条目，磁盘上的原始文件不受影响。

```ts
const analysis = new Analysis()                         // 默认：索引无界
analysis.on('frame', row => { /* 新索引的帧 */ })
await analysis.watch('/path/to/growing.pcap')           // tail 文件；reducer 收到 phase 'live'

// 长跑 tail 的可选内存护栏：
// new Analysis({maxFrames: 1_000_000})  // 超上限 FIFO 驱逐最老帧 → 内存有界
```

## 浏览器

门面环境无关——注入浏览器 worker 通道；worker 是打包后的 `analysisWorkerBrowser` 入口
（esbuild + Buffer polyfill），source 是 `File`/`Blob`：

```ts
import {Analysis, WebWorkerChannel} from '@netkitty/analysis'

const worker = new Worker(/* 打包后的 analysisWorkerBrowser.js */)
const analysis = new Analysis({}, () => new WebWorkerChannel(worker))
await analysis.open(file)   // file：一个 File/Blob
```

node 与浏览器结果逐字段一致。

## 旧接口（保留）

批处理式的 `FlowAnalyzer` 与 `TcpStreamAnalyzer`（吃内存中的 `AnalysisPacket[]`）仍然导出且未改动。
