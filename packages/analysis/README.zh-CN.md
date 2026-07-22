<p align="center">
  <img src="https://raw.githubusercontent.com/myq1991/netkitty/main/assets/NetKittyLogo.webp" alt="NetKitty" width="180">
</p>

# @netkitty/analysis

对抓包文件做流式的跨包分析——一个可编程的、类似 Wireshark 的 pcap/pcapng 入口。同一个 `Analysis` 类
**在 Node 和浏览器里都能用**:读取、解析、部分解码、建立索引这些重活都放在一个后台工作线程里做,所以
`open()` 不会卡住调用方,`close()` 只要结束这个线程,就能把占用的内存一次性全部释放。

> English docs: [README.md](./README.md)

它底层用到 [`@netkitty/codec`](../codec)(协议解码)和 [`@netkitty/pcap-core`](../pcap-core)
(pcap/pcapng 解析),两者都只处理内存里的字节,可以安全地在浏览器中运行。

## 安装

```bash
npm i @netkitty/analysis
# 或者用聚合包:import ... from 'netkitty/analysis'
```

## 快速上手(Node)

```ts
import {Analysis, ConversationsReducer} from '@netkitty/analysis'

const analysis = new Analysis()
await analysis.open('/path/to/capture.pcap')      // 读一个完整文件:建好索引,完成后触发 'complete'

analysis.frameCount()                              // 已索引的总帧数
const rows = await analysis.getFrames(0, 100)      // 轻量的帧行(不含解码后的各层)
const frame = await analysis.getFrame(42)          // 单帧,含解码后的各层
const tcp = await analysis.filter('tcp')           // 命中的帧序号

const conversations = new ConversationsReducer()
await analysis.attachReducer(conversations)        // 先把已索引的历史帧全部重放,再跟随后续实时帧
conversations.result()                             // 随时取当前结果(没有收尾这一步)

await analysis.close()                             // 结束工作线程,释放全部内存
```

## 什么是 reducer

reducer 是一个可插拔的、"边读边算"的统计器:每来一帧都会喂给它,你随时都能用 `result()` 拿到当前的
统计结果(没有"结束/收尾"这一步)。调用 `attachReducer` 时,它会先把已经建好索引的历史帧整个重放一遍,
再继续跟着后续的新帧走——所以这个方法一返回,统计结果就已经是完整的("一打开,统计就在那儿")。

- **内置(已导出)**:`ConversationsReducer`、`EndpointsReducer`、`TcpStreamReducer`
  (统计重传、重复 ACK、往返时延)。其中会话表和端点表建议直接用快捷方法 `analysis.conversations()`
  和 `analysis.endpoints()`——它们**全程在工作线程里**扫描索引列算出同样的结果,不重新解码、不逐帧在
  线程之间搬数据、主线程几乎不干活,所以哪怕上亿帧也很快。
- **便利工厂**:`reduceReducer(seed, fold)`、`groupByReducer(keyOf, seed, fold)`,用来快速拼一个
  简单的 reducer。
- **自定义**:实现 `IAnalysisReducer<T>` 接口——见下面的[编写自定义 reducer](#编写自定义-reducer)。

```ts
import {reduceReducer, groupByReducer} from '@netkitty/analysis'

const totalBytes = reduceReducer(0, (sum, frame) => sum + frame.length)
const perProtocol = groupByReducer(f => f.topProtocol, 0, count => count + 1)
```

### 编写自定义 reducer

一个 reducer 就是实现了 `IAnalysisReducer<T>` 的普通对象或类:

```ts
interface IAnalysisReducer<T> {
  update(frame: Frame, context: UpdateContext): void  // 每来一帧调用一次(先重放历史,再走实时)
  result(): T                                          // 随时取当前结果,没有收尾这一步
  reset(): void                                        // 清空已累积的状态
  readonly needs?: string[]                            // 可选:声明你会用到哪几层协议
  readonly indexOnly?: boolean                         // 可选:一条关乎正确性的约定,见下文
}
```

- **`update(frame, context)`**:每来一帧调用一次。`frame` 里有 `index`、`timestamp`、`length`、
  `topProtocol`、`conversationKey`,以及 `layers`(解码好的各层协议)。`context` 里有 `index`、
  `total` 和 `phase`——重放历史帧时是 `'replay'`,用 `watch()` 跟读实时流时是 `'live'`。
- **`result()`**:随时都能调,返回当前这一刻的统计结果,没有收尾这一步。**`reset()`**:清空已累积的
  状态。
- 累积状态时请按**会话或端点**来聚合,不要一帧一条地堆。内置 reducer 只记录每个会话首帧和末帧的序号,
  而不是把所有成员帧列出来,所以就算几亿帧,内存占用也基本是平的。
- **`needs`(可选)**:声明你真正会读到的协议层,比如 `['ipv4', 'tcp']`。这样工作线程只把这几层的
  数据回传给你,而不是整棵协议树——纯粹省流量,不影响结果。
- **`indexOnly`(可选,是一条关乎正确性的约定,不只是性能开关)**:只有当你的 `update` 除了帧的基本
  信息(`index`、`timestamp`、`length`、`topProtocol`、`conversationKey`)之外,**只读取五元组**——
  也就是收发双方的地址和端口(`eth` 的 `smac`/`dmac`,`ipv4`/`ipv6` 的 `sip`/`dip`,`tcp`/`udp`
  的 `srcport`/`dstport`)——时,才可以设成 `true`。设成 `true` 之后,重放历史帧会直接用索引列拼出
  帧、跳过逐帧重新解码,实测在大文件上快大约 13 倍。⚠️ 但如果你设了 `true`,却又读了更深的字段(比如
  `ipv4.ttl`、`tcp.flags`、TLS 的 SNI、载荷等),这些字段在重放时是**取不到的**,结果会悄悄算错。
  拿不准就别设,默认走完整解码最稳妥。内置的 `ConversationsReducer` 和 `EndpointsReducer` 设了它
  (只用五元组);`TcpStreamReducer` 没设(因为它要读序列号、确认号、标志位)。

```ts
import {IAnalysisReducer, Frame, UpdateContext} from '@netkitty/analysis'

// 按顶层协议统计帧数。只读基本信息,所以设 indexOnly 是安全的。
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

reducer 是跑在**主线程**上的——它的 `update` 是个函数,没办法被复制到工作线程里去执行。这不要紧:
`update` 本身只是些很轻的加加减减;真正费时的读取和解码早在工作线程里做完了,而 `indexOnly` 和 `needs`
决定了其中有多少数据要回传到主线程。如果需要,reducer 还可以顺带继承一个事件发射器,在 `update()`
里推送自己的 `progress`/`update` 事件。

## 实时抓包(watch)

`watch()` 会持续跟读一个还在不断写入的抓包文件,把每一新帧以 `'live'` 阶段喂给 reducer。索引**默认
不设上限**(内存多少由你自己把控)。`maxFrames` 是一个可选的内存护栏:一旦超过这个数,就按先进先出的
方式淘汰最老的索引条目(类似 Wireshark 的环形缓冲),让长时间跟读也能把内存控制住——注意这只丢内存里
的索引,磁盘上的原始文件不受影响。

```ts
const analysis = new Analysis()                         // 默认:索引不设上限
analysis.on('frame', row => { /* 新索引到的一帧 */ })
await analysis.watch('/path/to/growing.pcap')           // 跟读文件;reducer 收到 'live' 阶段

// 长时间跟读时的可选内存护栏:
// new Analysis({maxFrames: 1_000_000})  // 超出上限就先进先出淘汰最老的帧 → 内存有上限
```

## 浏览器

`Analysis` 这个入口本身不依赖具体运行环境——你只要给它注入一个浏览器版的工作线程通道就行。这个工作线程
是打包好的 `analysisWorkerBrowser` 入口(用 esbuild 打包,并带上 Buffer 垫片),数据源换成 `File`
或 `Blob`:

```ts
import {Analysis, WebWorkerChannel} from '@netkitty/analysis'

const worker = new Worker(/* 打包后的 analysisWorkerBrowser.js */)
const analysis = new Analysis({}, () => new WebWorkerChannel(worker))
await analysis.open(file)   // file 是一个 File/Blob
```

Node 和浏览器下算出来的结果逐字段完全一致。
