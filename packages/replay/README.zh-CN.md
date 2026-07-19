# @netkitty/replay

基于原生插件的报文重放与流量生成——把帧从真实网卡发出去,既可以**精准复现录制时的帧间时序**(精准重
放),也可以**维持某个目标速率**(流量生成)。它会自动挑选当前平台上最快的发包后端(Linux 上是
TX_RING / PF_PACKET,BSD/macOS 上是 BPF,Windows 上是 Npcap),整个发送循环都跑在一条**专用原生线
程**上,绝不阻塞 Node 事件循环——进度、完成和错误都通过事件回传。

> English docs: [README.md](./README.md)

精准重放所需的时序,来自 [`@netkitty/pcap`](../pcap):它会从 pcap/pcapng/cap 文件里解析出每一帧的
`seconds`/`nanoseconds`。

## 安装

```bash
npm i @netkitty/replay
# 或者用聚合包:import ... from 'netkitty/replay'
```

原生插件在安装时用 node-gyp 从源码本地编译——**本项目绝不发布预编译二进制**。你需要一套可用的 C/C++
编译工具链,外加 pcap 开发头文件:Linux 上装 `libpcap-dev`,BSD/macOS 自带 libpcap 头文件,Windows
上装 [Npcap](https://npcap.com) 及其 SDK。发包通常需要较高权限(root、`CAP_NET_RAW`、管理员终端,或
加入 bpf 用户组),请据此运行你的程序。

网卡名可以用 [`@netkitty/iface`](../iface) 的 `list()` 查询。

## 快速上手

### 精准重放一个抓包文件

原样复现文件里录制的帧间时序:

```ts
import {replayFile} from '@netkitty/replay'

const replay = await replayFile('capture.pcap', {device: 'en0'})   // 默认模式 multiplier,rate 为 1
replay.on('progress', (s) => console.log(`${s.sent} 帧,${s.mbps.toFixed(1)} Mbps`))
replay.on('done', (s) => console.log(`在 ${s.backend} 上完成:发出 ${s.sent} 帧,失败 ${s.failed} 帧`))
replay.on('error', (e) => console.error(e))
replay.start()
```

`replayFile` 会把整个抓包文件读进内存,返回一个**尚未启动**的 `Replay`——请先挂好监听,再调用
`start()`。

### 流量生成

按网卡能接受的最快速度、不做任何节流地把一批帧发出去:

```ts
import {Replay, loadFrames} from '@netkitty/replay'

const replay = new Replay({device: 'eth0', mode: 'topspeed'})
replay.addFrames(await loadFrames('capture.pcap'))   // 也可以自己构造帧
replay.on('done', (s) => console.log(s))
replay.start()
```

帧就是二层的原始字节,所以你完全可以自己拼(如需修改,可先用 [`@netkitty/codec`](../codec) 编辑):

```ts
const replay = new Replay({device: 'eth0', mode: 'pps', rate: 10000})
replay.addFrames([{data: myFrameBuffer}])            // 省略时间戳——multiplier 之外的模式本就不看它
replay.start()
```

### 辅助函数

- `loadFrames(file)` 把一个 pcap/pcapng/cap 文件(任意字节序,微秒或纳秒精度)整体读进内存,得到
  `IReplayFrame[]`,并保留每一帧的时间戳,供 `multiplier` 模式使用。
- `isSendAvailable()` 探测 pcap 发包路径能否打开。在 Windows 上它会加载 `wpcap.dll`,当没有安装
  Npcap 时返回 `false`——这主要是给 Windows 判断就绪状态用的(POSIX 上的原生 PF_PACKET/BPF 后端并不
  需要它)。该函数不会抛异常。

## 帧结构

```ts
interface IReplayFrame {
  data: Buffer          // 完整的二层帧,原样发送
  seconds?: number      // 抓包时间戳——只有 multiplier 模式会读取
  nanoseconds?: number  // 时间戳的亚秒部分
}
```

在 `topspeed`、`mbps`、`pps` 三种模式下时间戳会被忽略,所以纯流量生成时可以不填。

## 选项

`new Replay(options)` / `replayFile(file, options)`——`IReplayOptions` 的每一个字段:

| 选项 | 类型 | 默认值 | 含义 |
| --- | --- | --- | --- |
| `device` | `string` | *(必填)* | 用于发包的网卡(`en0` / `eth0` / 一个 Npcap 设备字符串)。 |
| `mode` | `ReplayMode` | `'multiplier'` | 节流模式——见下文。 |
| `rate` | `number` | `1` | 对应模式的速率:倍率 / 兆比特每秒 / 包每秒。 |
| `loop` | `number` | `1` | 把整批帧重放几遍。 |
| `infinite` | `boolean` | `false` | 无限循环(会覆盖 `loop`)。 |
| `loopDelayMs` | `number` | `0` | 每遍之间的停顿,单位毫秒。 |
| `limit` | `number` | `0` | 发够这么多帧后停止(`0` 表示不限)。 |
| `maxSleepMs` | `number` | `0` | 把任何单次帧间等待钳制在最多这么多毫秒(`0` 表示不钳制)——用来跳过录制里长时间的空闲间隔很方便。 |
| `precision` | `ReplayPrecision` | `'auto'` | 节流模式下的时序精度——见下文。 |
| `realtime` | `boolean` | `false` | 为发送线程申请实时调度。 |
| `cpu` | `number \| 'auto'` | *(不绑核)* | 把发送线程绑到某个 CPU 核心上,以降低时序抖动。 |
| `validateDevice` | `boolean` | `true` | 启动前先校验设备是否存在。 |

### 模式(`mode` 配合 `rate`)

- **`multiplier`**——复现录制的帧间时序,并按 `rate` 缩放:`1` 是原速,`2` 是两倍快,`0.5` 是半速。
  这就是精准重放,也是唯一会读取帧时间戳的模式。
- **`topspeed`**——按网卡能接受的最快速度发送,不做节流(`rate` 被忽略)。用于流量生成。
- **`mbps`**——维持平均 `rate` 兆比特每秒的吞吐。
- **`pps`**——维持平均 `rate` 个包每秒的速率。

### 精度(`precision`,仅节流模式)

- **`auto`**(默认)——每个间隔的大部分用休眠度过,最后约 250µs 用忙等自旋,以保证准头。
- **`sleep`**——一律休眠:CPU 占用更低,时序更粗。
- **`spin`**——更激进地忙等自旋:精度最高,CPU 占用也最高。

### 抖动与调度(`realtime`、`cpu`)

发送线程始终会被施加一档安全的优先级提升。在此之外:

- **`realtime`** 申请实时调度(POSIX `SCHED_FIFO` / Windows `TIME_CRITICAL`),以获得尽可能紧的时序。
  它需要较高权限才能生效,而且可能独占一个 CPU 核心——除非确实需要,否则别开。
- **`cpu`** 把发送线程绑到某一个核心上,阻止调度器在核心之间迁移它,从而降低抖动。填**数字**表示绑到
  那个从 0 开始编号的核心;填 **`'auto'`** 表示在进程被允许使用的核心集合里挑编号最高的一个(跳过 0
  号核,并尊重 `taskset`/cgroup 的限制)。尽力而为:在 Linux 和 Windows 上有效;macOS 没有真正的按核
  绑定,所以那里会被忽略。不填则让线程保持不绑核(默认如此——自动绑核是需要显式开启的,因为在小型或
  共享主机上它反而可能帮倒忙)。

## 发包后端

插件会打开当前平台上可用的最快后端,若某个原生后端打不开就**自动回退到 pcap**。`progress`/`done`
事件里的 `backend` 字段会告诉你实际用的是哪个。

| 平台 | 优先级(从高到低) | `backend` 取值 |
| --- | --- | --- |
| Linux | TX_RING(PACKET_MMAP) → PF_PACKET(裸 `AF_PACKET`) → pcap | `tx_ring` / `pf_packet` / `pcap` |
| BSD / macOS | BPF(`/dev/bpf`) → pcap | `bpf` / `pcap` |
| Windows | pcap(Npcap,运行时动态加载 `wpcap.dll`) | `pcap` |

## API

```ts
class Replay extends EventEmitter {
  constructor(options: IReplayOptions)
  addFrames(frames: IReplayFrame[]): void   // 排入待发帧;start() 之前可多次调用
  start(): void                             // 在发送线程上开始发送(运行中重复调用无副作用)
  stop(): void                              // 请求发完当前帧后停止;之后仍会触发一次 'done'
  get running(): boolean                    // 发送期间为 true

  on('progress', (p: IReplayProgress) => void): this
  on('done',     (p: IReplayProgress) => void): this   // 有且仅有一次终结的 done……
  on('error',    (e: Error) => void): this             // ……或一次 error
}
```

`addFrames` 会立刻把帧复制进原生内存,所以调用之后源缓冲区可以马上复用。`start()` 之后,`progress`
会定期触发,最终恰好触发一次终结事件:`done`(带最终统计)或 `error`。

### 进度(`progress` / `done` 的载荷)

```ts
interface IReplayProgress {
  sent: number       // 到目前为止成功发上线的帧数
  bytes: number      // 到目前为止成功发送的字节数
  failed: number     // 被后端拒绝(发送出错)的帧数
  elapsedMs: number  // 从本次运行开始起的实际耗时
  loop: number       // 当前是第几遍(从 0 开始)
  pps: number        // 实际达到的速率,包每秒(按整段运行至今计)
  mbps: number       // 实际达到的吞吐,兆比特每秒(按整段运行至今计)
  backend: string    // 实际使用的发包后端(见上表)
}
```

## 绝不发布预编译二进制

按项目铁律,本包永不附带编译好的 `.node` 文件——原生插件一律在安装时从源码本地编译。请确保
[安装](#安装)一节列出的工具链和 pcap 头文件已就绪,并记住:发帧通常需要较高权限。
