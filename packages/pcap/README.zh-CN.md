# @netkitty/pcap

在 Node.js 端流式地读取、写入和解析抓包文件——支持 pcap、pcapng,以及经典的 `.cap`/tcpdump 输出,全程
不依赖具体格式。`PcapReader` 和 `PcapWriter` 都基于 `node:fs` 的文件句柄做流式处理,所以再大的抓包也
不必整个装进内存;`PcapReader` 还能跟读一个仍在写入的文件。

> English docs: [README.md](./README.md)

`PcapParser` 只是一层很薄的 `EventEmitter` 外壳,把读取流喂给 [`@netkitty/pcap-core`](../pcap-core)
——一个只处理内存字节、可以安全在浏览器里运行的解析内核,真正的字节活儿都在它那里做(靠魔数识别格式、
解析两种字节序和微秒/纳秒变体的经典 pcap,以及 pcapng)。

## 安装

```bash
npm i @netkitty/pcap
# 或者用聚合包:import ... from 'netkitty/pcap'
```

## 快速上手

### 读取抓包

`PcapReader` 会逐包扫过文件,每个包报告一份 `IPcapPacketInfo`——序号、时间戳,以及这条记录在文件里的
字节范围。要拿整帧字节,调用 `readPacketData(info)`;它用的是解析器报告的 `packetOffset` 和
`packetLength`,所以对 pcap 和 pcapng 都一样成立。

```ts
import {PcapReader, IPcapPacketInfo} from '@netkitty/pcap'

const reader = new PcapReader({
  filename: '/path/to/capture.pcap',
  onPacket: async (info: IPcapPacketInfo): Promise<void> => {
    const frame: Buffer = await reader.readPacketData(info)   // 整帧字节,pcap 或 pcapng 通用
    console.log(`#${info.index} @${info.seconds}.${info.microseconds} — ${frame.length} 字节`)
  }
})

reader.on('done', (): void => console.log('已读到文件末尾'))
await reader.start()   // 一直读到末尾,然后触发 'done'
```

`onPacket` 可以是异步的——在它执行期间读取流会被暂停,结束后再恢复,所以背压是自动的,await 的过程中不会
丢包。同样的信息也会以 `packet` 事件抛出,如果你更喜欢用监听器而不是回调,可以改用它。

### 写入抓包

`PcapWriter` 会新建一个经典 pcap 文件(先写好全局头),或者往已存在的文件后面追加,再用 `write()` 把
每一帧流式写出。传入帧的字节,以及拆成整秒和不足一秒的微秒余数两部分的抓包时间戳。

```ts
import {PcapWriter} from '@netkitty/pcap'

const writer = new PcapWriter({filename: '/path/to/out.pcap'})

const now: number = Date.now()
writer.write(frameBytes, Math.floor(now / 1000), (now % 1000) * 1000)

await writer.close()   // 刷新并关闭文件句柄
```

每写入一个包都会触发 `packet` 事件,携带这一帧落盘后的 `IPcapPacketInfo`(偏移、长度、时间戳)。
`wroteCount` 记录已经写了多少帧。

### 跟读还在增长的文件

设置 `watch: true`,读取器读到当前末尾后不会停,而是继续跟着文件走,文件一有新帧追加就接着读出来——把
一个 `PcapWriter` 和一个开了 watch 的 `PcapReader` 配对,就能一边录制一边消费同一份抓包。

```ts
const reader = new PcapReader({filename: '/path/to/growing.pcap', watch: true, onPacket})
await reader.start()   // watch 模式下不会自己走到 'done',要靠你调 stop()/close() 才停
await reader.stop()    // 或者用 reader.close(),它会顺带移除所有监听器
```

## 关键概念

- **不依赖格式。** 读取器并不关心文件是 pcap 还是 pcapng;`@netkitty/pcap-core` 会从魔数自动识别格式,
  两种字节序、经典 pcap 的微秒和纳秒变体,以及 pcapng 的段/接口/包各类区块都能处理。
  `reader.parser.format` 会给出识别到的 `PcapFileFormat`(`'pcap' | 'pcapng'`)。
- **按 info 取字节,不靠猜。** `readPacketData(info)` 会定位到解析器报告的 `packetOffset`,精确读出
  `packetLength` 个字节,所以对每种格式都是对的。旧的 `readPacket(offset, length)` 已**弃用**——它
  假设记录头是固定的 16 字节经典 pcap 格式,只对经典 pcap 文件有效。
- **全程流式。** 读取器和写入器都基于文件句柄按 `chunkSize` 分块处理(默认 `1518 * 10` 字节),所以
  不论文件多大,内存占用都是平的。

## API

### `new PcapReader(options)`

| 选项        | 类型                                          | 默认值       | 含义                                       |
| ----------- | --------------------------------------------- | ------------ | ------------------------------------------ |
| `filename`  | `string`                                      | —            | 要读取的抓包文件路径                       |
| `watch`     | `boolean`                                     | `false`      | 读到当前末尾后继续跟读文件                 |
| `chunkSize` | `number`                                      | `1518 * 10`  | 每次文件读取的字节数                       |
| `onPacket`  | `(info: IPcapPacketInfo) => Promise \| void`  | —            | 逐包回调;它 await 期间读取会被暂停         |
| `onStart`   | `() => Promise \| void`                       | —            | `start()` 开始时触发                       |
| `onStop`    | `() => Promise \| void`                       | —            | 停止读取时触发                             |
| `onDone`    | `() => Promise \| void`                       | —            | 读到文件末尾时触发                         |
| `onError`   | `(err: Error) => void`                        | —            | 解析/读取出错                              |

- `start(): Promise<void>`——重置并开始读取(直读到末尾,或在 `watch` 下持续跟读)。
- `stop(): Promise<void>`——停止读取并拆除底层流。
- `close(): Promise<void>`——先停止,再移除所有监听器。
- `readPacketData(info: IPcapPacketInfo): Promise<Buffer>`——取某个已报告包的整帧字节。
- `readPacket(offset, length): Promise<Buffer>`——**已弃用**,仅适用于经典 pcap。
- 事件:`packet`(`IPcapPacketInfo`)、`start`、`stop`、`done`、`close`、`error`。

### `new PcapWriter(options)`

| 选项                | 类型      | 默认值 | 含义                                                     |
| ------------------- | --------- | ------ | -------------------------------------------------------- |
| `filename`          | `string`  | —      | 输出路径;不存在则新建(带头),已存在则追加              |
| `includePacketData` | `boolean` | `true` | 在触发的 `packet` 信息里附带 base64 形式的原始字节       |

当消费方只需要元数据时,把 `includePacketData` 设成 `false`——这样会跳过每个包的 base64 编码;字节仍然
会正常写入文件。

- `write(packet: Buffer, seconds: number, microseconds: number): void`——追加一帧及其时间戳。
- `close(): Promise<void>`——刷新并关闭文件句柄。
- `wroteCount: number`——目前已写入的帧数。
- 事件:`packet`(`IPcapPacketInfo`)。

### `PcapParser`

`PcapReader` 内部使用的流式外壳,你也可以直接驱动它。

- `PcapParser.parse(input: string | ReadStream): PcapParser`——基于文件路径或读取流创建解析器。
- `format: PcapFileFormat | null`——识别出格式后给出的格式名。
- 事件:`globalHeader`、`sectionHeader`、`packetHeader`、`packetData`、`packet`(`IPcapPacketInfo`)、
  `end`、`error`。

### 从 [`@netkitty/pcap-core`](../pcap-core) 再导出

`IPcapPacketInfo`、`PcapFileFormat`,以及经典 pcap 的字节生成器 `GeneratePCAP`、`GeneratePCAPHeader`、
`GeneratePCAPData`(配套类型 `GeneratePCAPInputPacket` / `GeneratePCAPPacket`)。
