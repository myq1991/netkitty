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

- **内置**（已导出）：`ConversationsReducer`、`EndpointsReducer`、`TcpStreamReducer`
  （重传 / 重复 ACK / RTT）。Conversations/Endpoints 建议用快捷方法 `analysis.conversations()` /
  `analysis.endpoints()`——它们**完全在 worker 内**扫索引列算出同样的结果（不重解码、不逐帧跨线程、
  主线程零负担），所以哪怕上亿帧也很快。
- **便利工厂**：`reduceReducer(seed, fold)`、`groupByReducer(keyOf, seed, fold)`。
- **自定义**：实现 `IAnalysisReducer<T>` —— 见 [编写自定义 reducer](#编写自定义-reducer)。

```ts
import {reduceReducer, groupByReducer} from '@netkitty/analysis'

const totalBytes = reduceReducer(0, (sum, frame) => sum + frame.length)
const perProtocol = groupByReducer(f => f.topProtocol, 0, count => count + 1)
```

### 编写自定义 reducer

reducer 是一个实现 `IAnalysisReducer<T>` 的普通对象（或类）：

```ts
interface IAnalysisReducer<T> {
  update(frame: Frame, context: UpdateContext): void  // 逐帧调用（先回放，后实时）
  result(): T                                          // 滚动快照 —— 随时可取，没有 finalize
  reset(): void                                        // 清空全部累积状态
  readonly needs?: string[]                            // 可选：你读取的协议层 id（投影）
  readonly indexOnly?: boolean                          // 可选：正确性/性能契约，见下
}
```

- **`update(frame, context)`** 每帧调用一次。`frame` 带有 `index`、`timestamp`、`length`、
  `topProtocol`、`conversationKey`，以及 `layers`（解码后的协议树）。`context` 带有 `index`、
  `total` 和 `phase` —— 回放已索引积压时为 `'replay'`，`watch()` 跟随实时流时为 `'live'`。
- **`result()`** 是滚动快照，**没有 finalize**，任何时刻都能调用（回放途中、tail 途中）。
  **`reset()`** 清空状态。
- 状态请按**会话/端点**收敛，而不是按帧累积 —— 内置 reducer 只保留首/末帧的 index 跨度，而非成员帧
  列表，所以在数亿帧下内存仍然平坦。
- **`needs`**（可选）：你实际读取的协议层 id，例如 `['ipv4', 'tcp']`。worker 只把这些层跨线程传回，
  而不是整棵树 —— 纯带宽优化，不改变行为。
- **`indexOnly`**（可选 —— 一条**正确性契约**，不只是提示）：**仅当** `update` 只读取帧元信息
  （`index` / `timestamp` / `length` / `topProtocol` / `conversationKey`）和 `layers` 里的五元组
  —— 端点地址与端口（`eth` 的 `smac`/`dmac`、`ipv4`/`ipv6` 的 `sip`/`dip`、`tcp`/`udp` 的
  `srcport`/`dstport`）—— 时才设为 `true`。此时回放会直接**用索引列合成帧、跳过逐帧重新解码**，实测在
  大文件上快约 13×。⚠️ 如果你设了它却读取了任何更深的字段（`ipv4.ttl`、`tcp.flags`、TLS SNI、载荷
  ……），该字段在回放时会直接**缺失**，结果会静默出错。拿不准就别设 —— 完整解码是安全默认值。
  `ConversationsReducer`、`EndpointsReducer` 设了它（只用五元组）；`TcpStreamReducer` 没设（它要读
  seq/ack/flags）。

```ts
import {IAnalysisReducer, Frame, UpdateContext} from '@netkitty/analysis'

//按顶层协议统计帧数。只读元信息 → indexOnly 安全。
class ProtocolCounter implements IAnalysisReducer<Record<string, number>> {
  readonly indexOnly = true
  #counts: Record<string, number> = {}
  update(frame: Frame, _context: UpdateContext): void {
    this.#counts[frame.topProtocol] = (this.#counts[frame.topProtocol] ?? 0) + 1
  }
  result(): Record<string, number> { return {...this.#counts} }
  reset(): void { this.#counts = {} }
}
```

reducer 运行在**主线程**上 —— 它的 `update` 闭包无法被结构化克隆进 worker。这没问题：`update` 只是廉价
的算术；真正昂贵的部分（读取 + 解码）已经在 worker 里完成，而 `indexOnly`/`needs` 决定其中多少需要传回
主线程。reducer 也可以额外继承事件发射器，在 `update()` 内推送自己的 `progress`/`update` 事件。

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
