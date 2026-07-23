<p align="center">
  <img src="https://raw.githubusercontent.com/myq1991/netkitty/main/assets/NetKittyLogo.webp" alt="NetKitty" width="180">
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/@netkitty/pcap-core"><img src="https://img.shields.io/npm/v/@netkitty/pcap-core?style=flat-square&labelColor=162032&color=2979ff&logo=npm&logoColor=white" alt="npm version"></a>
  <a href="https://www.npmjs.com/package/@netkitty/pcap-core"><img src="https://img.shields.io/npm/dm/@netkitty/pcap-core?style=flat-square&labelColor=162032&color=22c55e&logo=npm&logoColor=white" alt="npm downloads"></a>
  <a href="https://github.com/myq1991/netkitty/blob/main/LICENSE"><img src="https://img.shields.io/npm/l/@netkitty/pcap-core?style=flat-square&labelColor=162032&color=2979ff" alt="license"></a>
</p>

# @netkitty/pcap-core

一个只处理内存字节的 pcap/pcapng 解析状态机、生成器与 LZ4 解压器——**不依赖任何 node 模块、可以安全地
在浏览器里运行**(全程只用 Buffer,不碰 `node:fs`、`events`、`node:util`)。它不靠 EventEmitter,而是靠
**注入回调**来交付结果:你用一组回调把它构造出来,再用 `write(chunk)` 把字节喂进去,它就会同步地驱动
内部状态机,每解析出一个头或一个包就回调你一次。

> English docs: [README.md](./README.md)

这是最底层的核心。如果你在 Node 端需要流式读取(基于 `node:fs`、EventEmitter 风格的接口、随机访问),
请用 [`@netkitty/pcap`](../pcap);如果要做跨包的、类似 Wireshark 的分析,请用
[`@netkitty/analysis`](../analysis)。当你手里已经有了字节(浏览器里的 `File`/`Blob`、一段
WebSocket 数据、内存里的抓包内容),只想把它解析出来时,就直接用 `@netkitty/pcap-core`。

## 安装

```bash
npm i @netkitty/pcap-core
```

## 快速上手——解析

用你关心的那几个回调构造一个 `PcapParserCore`,再把字节推进去。数据块大小不限——解析器会把不完整的
记录先缓存起来,凑齐一整个包之后才调用 `onPacket`,所以把一个文件切成 64 KB 一块一块喂进去,和一次性
`write` 整个文件,结果完全一样。

```ts
import {PcapParserCore, IPcapPacketInfo} from '@netkitty/pcap-core'

const parser = new PcapParserCore({
  onGlobalHeader: header => console.log('经典 pcap 全局头', header),      // 仅经典 pcap
  onSectionHeader: header => console.log('pcapng 段头', header),         // 仅 pcapng
  onPacket: (info: IPcapPacketInfo) => {
    console.log(info.index, info.seconds, info.microseconds, info.nanoseconds)
    console.log(info.packet)   // 抓到的字节,base64 编码
  },
  onEnd: () => console.log('解析完成'),
  onError: err => console.error('文件损坏:', err.message)
})

// 想怎么切块喂都行;解析器会根据 magic number 自动分辨 pcap 还是 pcapng
parser.write(someBuffer)
parser.write(moreBuffer)
parser.end()

parser.format   // 'pcap' | 'pcapng' | null——收到开头几个字节后就确定了
```

每个包都会以一个 `IPcapPacketInfo` 交付:

```ts
interface IPcapPacketInfo {
  index: number               // 从 1 开始的包序号
  offset: number              // 该记录/块在文件中的字节偏移
  length: number              // 该记录/块的总字节长度
  recordHeaderOffset: number  // 记录/块头部的字节偏移
  recordHeaderLength: number  // 包数据前头部的长度
  packetOffset: number        // 抓到的包数据的字节偏移
  packetLength: number        // 抓到的包的字节长度
  seconds: number             // 时间戳——整秒部分
  microseconds: number        // 不足一秒的部分,微秒(0..999_999)
  nanoseconds: number         // 不足一秒的部分,纳秒(0..999_999_999)
  packet: string              // 抓到的包字节,base64 编码
}
```

其余回调都是可选的,和解析器各个阶段一一对应:`onGlobalHeader`(经典 pcap 的 24 字节全局头)、
`onSectionHeader`(pcapng 的段头块)、`onPacketHeader`(逐包的记录头,两种格式已归一化),以及
`onPacketData`(抓到的原始 `Buffer`,在 `onPacket` 之前紧接着交付)。

## 快速上手——生成

`GeneratePCAP` 把一组 base64 的帧拼成一个完整的经典 pcap 文件缓冲(链路层默认按以太网)。如果想一条
一条地把记录流式输出,就用拆开的 `GeneratePCAPHeader` / `GeneratePCAPData`。

```ts
import {GeneratePCAP, GeneratePCAPHeader, GeneratePCAPData} from '@netkitty/pcap-core'

// 一次调用生成整个文件
const file: Buffer = GeneratePCAP([
  {frameBase64Data: base64Frame, timestamp: Date.now()},                       // 时间戳,毫秒
  {frameBase64Data: base64Frame, microsecond: {seconds: 1_700_000_000, microseconds: 123_456}}
])

// 或者自己一条记录一条记录地拼
const chunks: Buffer[] = [GeneratePCAPHeader()]
chunks.push(GeneratePCAPData({buffer: rawFrame, timestamp: Date.now()}))
const alsoAFile: Buffer = Buffer.concat(chunks)
```

`GeneratePCAP` 接收 `frameBase64Data`,外加 `timestamp`(毫秒)或明确的
`microsecond: {seconds, microseconds}` 二者之一;`GeneratePCAPData` 参数相同,只是把 base64 换成
原始的 `buffer`。生成的结果可以原样往返:再喂回 `PcapParserCore`,就能把这些帧原封不动地取回来。时间戳
会被夹到安全范围(负数/NaN/小数都不会抛异常),微秒溢出会进位到秒。

### 生成 pcapng

`GeneratePcapng` 则生成一个 **pcapng** 文件——一个段头块(SHB)、一个接口描述块(IDB),然后每帧一个
增强型包块(EPB)(小端、微秒时间戳)。它接收和 `GeneratePCAP` 一样的 `frameBase64Data` +
`timestamp`/`microsecond` 输入,外加可选的 `{linkLayerType, snapshotLength}`。拆开的
`GeneratePcapngSectionHeader` / `GeneratePcapngInterfaceDescription` / `GeneratePcapngEnhancedPacket`
让你按块自己拼。

```ts
import {GeneratePcapng} from '@netkitty/pcap-core'

const pcapng: Buffer = GeneratePcapng([
  {frameBase64Data: base64Frame, microsecond: {seconds: 1_700_000_000, microseconds: 123_456}}
], {linkLayerType: 1})   // 1 = 以太网
```

## 解压 LZ4

`Lz4FrameDecompress(buffer)` 把一个 **LZ4 frame 格式**的缓冲(魔数 `04 22 4d 18`)解回原始字节——一个
零依赖、浏览器安全的纯 JS 解码器(只解压)。[`@netkitty/pcap`](../pcap) 就是用它来透明读取 `.lz4`
压缩抓包的;如果你自己手里有字节,两行就能先解压再解析。

```ts
import {Lz4FrameDecompress, PcapParserCore} from '@netkitty/pcap-core'

const raw: Buffer = Lz4FrameDecompress(lz4Bytes)   // 再把 `raw` 照常喂给 PcapParserCore
```

## 关键概念

- **格式靠 magic number 自动识别。** 经典 libpcap(`.pcap`/`.cap`/tcpdump 输出)的四种变体都能认——
  大端和小端、微秒和纳秒,pcapng 则靠它的段头块识别。你不需要告诉解析器手里是什么格式;开头四个字节
  一到,`parser.format` 就会报出识别到的格式。
- **纳秒精度,始终完整保留。** 经典的纳秒抓包会原样保留 `nanoseconds`,pcapng 则会遵循每个接口的
  `if_tsresol` 选项(以 10 或 2 为底的刻度分辨率),把 64 位时间戳换算成整秒加完整的纳秒小数部分。
  `seconds`、`microseconds`、`nanoseconds` 三者始终都会填好,消费方要多高精度就取多高。
- **面对损坏文件很稳健——内存有界、绝不抛异常。** 抓包长度和 pcapng 块长度都会对照 Wireshark 的上限
  做合理性检查,所以一个畸形的长度字段不会让解析器胡乱分配内存或空转。遇到坏文件它会停下来,通过
  `onError` 报告(而不是抛出异常);pcapng 里未知或过时的块(名称解析、接口统计、自定义块)会被跳过,
  而不会导致失败。

## 支持的格式

- **解析:** 经典 pcap 2.x(两种字节序,微秒和纳秒两种时间戳变体)和 pcapng——段头块(SHB)、接口
  描述块(IDB,含 `if_tsresol`)、增强型包块(EPB)、简单包块(SPB)、过时的包块;其余块类型一律跳过。
  LZ4 frame 格式的缓冲可以先用 `Lz4FrameDecompress` 解压。
- **生成:** 经典 pcap 2.4(`GeneratePCAP`)和 pcapng(`GeneratePcapng`),都是微秒精度。
