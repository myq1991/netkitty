<p align="center">
  <img src="https://raw.githubusercontent.com/myq1991/netkitty/main/assets/NetKittyLogo.webp" alt="NetKitty" width="180">
</p>

# NetKitty

一套面向 Node.js(在可行处也面向浏览器)的网络工具集:实时抓包、pcap/pcapng 读写、一个**既能解码也
能编码**报文头的 schema 驱动编解码器、流式的跨包分析、只读的网卡枚举,以及数据包重放与流量生成。它以
一个聚合包(`netkitty`)的形式发布,底层是一组职责单一的 `@netkitty/*` 包,组织在一个 workspaces
monorepo 里,你也可以单独安装其中任意一个。

> English docs: [README.md](./README.md)

## 子包一览

| 子包 | 从这里导入 | 做什么 | 运行环境 |
| --- | --- | --- | --- |
| [`@netkitty/codec`](./packages/codec) | `netkitty/codec` | schema 驱动地编解码 188 种报文头——Ethernet/VLAN/ARP、IPv4/6、TCP/UDP/SCTP、TLS、DNS/DHCP/HTTP,以及工控/OT 协议(GOOSE/SV、IEC 104、Modbus、DNP3、S7comm、MMS、CMS…) | Node + 浏览器 |
| [`@netkitty/pcap-core`](./packages/pcap-core) | (`netkitty/pcap` 的内核) | 纯字节的 pcap/pcapng 解析与生成,不依赖 Node | Node + 浏览器 |
| [`@netkitty/pcap`](./packages/pcap) | `netkitty/pcap` | Node 端流式读 / 写 / 解析 pcap/pcapng | Node |
| [`@netkitty/analysis`](./packages/analysis) | `netkitty/analysis` | 在工作线程里做流式的、类似 Wireshark 的跨包分析 | Node + 浏览器 |
| [`@netkitty/capture`](./packages/capture) | `netkitty/capture` | 基于 libpcap/Npcap 的实时抓包(原生插件) | Node |
| [`@netkitty/iface`](./packages/iface) | `netkitty/iface` | 只读枚举网卡、地址与收发统计(原生插件) | Node |
| [`@netkitty/replay`](./packages/replay) | `netkitty/replay` | 按录制时序重放 pcap,或生成流量(原生插件) | Node |
| [`netkitty`](./packages/netkitty) | — | 聚合包,通过子路径重新导出上面全部子包 | Node |

## 安装

```bash
# 一个依赖装下全部:
npm i netkitty

# 或者只装单个子包:
npm i @netkitty/codec
```

纯 TypeScript 的子包(`codec`、`pcap-core`、`analysis`)可安全在浏览器中运行。原生子包(`capture`、
`iface`、`replay`)会在安装时从源码编译一个原生插件——详见下文[原生插件与平台](#原生插件与平台)。

## 快速上手

解码再编码一个包——解码结果本身就是合法的编码输入,所以两者严格互逆:

```ts
import {Codec, HexToBuffer} from 'netkitty/codec'

const codec = new Codec()
const layers = await codec.decode(HexToBuffer('ffffffffffff0011223344550806...'))
// layers[0] => {id: 'eth', name: 'Ethernet II', data: {dmac, smac, etherType}, errors: []}

const {packet} = await codec.encode(layers) // 还原出原始字节
```

读一个抓包文件(pcap 或 pcapng,自动识别):

```ts
import {PcapReader, IPcapPacketInfo} from 'netkitty/pcap'

const reader = new PcapReader({
  filename: 'capture.pcap',
  onPacket: async (info: IPcapPacketInfo): Promise<void> => {
    const frame: Buffer = await reader.readPacketData(info)
    console.log(`#${info.index} — ${frame.length} 字节`)
  }
})
await reader.start()
```

按录制时序重放一个抓包(或用 `mode: 'topspeed'` 打流量):

```ts
import {replayFile} from 'netkitty/replay'

const replay = await replayFile('capture.pcap', {device: 'en0'})
replay.on('done', (s) => console.log(`在 ${s.backend} 上发出 ${s.sent} 帧`))
replay.start()
```

各子包的 README 里有完整 API 和更多示例。

## 设计取向(编解码器)

编解码器是**从图形化报文编辑器(一个"可编程的 Wireshark")倒推出来的**,而不是从追求吞吐的解析器出发。
每个协议头都是**一份可执行的 JSON Schema**,同一份声明同时扮演四个角色:字段树结构、每字段的
`decode`/`encode` 闭包、Ajv 输入校验(`useDefaults` 让 schema 兼任报文模板,`coerceTypes` 容忍表单
字符串输入),以及界面表单元数据(`label`、`hidden`、`contentEncoding`,加 `enum`/`const` 判别式)。
一次 `JSON.parse(JSON.stringify())` 往返把闭包剥掉,剩下可序列化的 schema 可直接交给前端渲染成可编辑
表单——这就是"声明式外壳"与"命令式内核"之间那条分界线。

有两条特性值得先知道:

- **解码永不失败。** 层间派发是一张 O(1) 的解复用表(`ethertype:` / `ipproto:` 键)加上 `RawData`
  兜底,所以未知或畸形的字节永远得到一份"尽力而为的结果 + 按字段路径定位的错误清单",而不是抛异常。
- **可以故意构造非法包。** 错误只累积、不抛出,而 `encode` 是**忠实执行者、不做语义裁判**——你给什么
  层、什么字段值(哪怕非法)它就照发。因此本库能用来做异常/畸形包测试,而且每一次 decode→encode 都是
  字节级还原。

完整阐述见 [`@netkitty/codec`](./packages/codec)。刻意不追求的两点:线速吞吐(每字段 async 闭包),以及
跨包重组(编解码器是单包的,重组属于它上面的一层)。

## 原生插件与平台

netkitty **绝不发布预编译二进制**。原生子包(`capture`、`iface`、`replay`)会在安装时于你本机用
node-gyp 从源码编译,所以你需要一套可用的 C/C++ 工具链:

- **macOS**:安装 Xcode 命令行工具(系统自带 libpcap)。
- **Linux**:一个编译器,外加 `libpcap-dev`(Debian/Ubuntu)或 `libpcap-devel`(RHEL/Fedora)。
- **Windows**:先装 [Npcap](https://npcap.com/);插件在运行时动态加载 `wpcap.dll`,所以编译只需头文件
  ——不打包任何 `.dll`/`.lib`/`.node`。

抓包和发包通常需要较高权限(root/管理员,或等价能力如 Linux 上的 `cap_net_raw`)。`@netkitty/iface`
是个例外:它只调用操作系统接口,不需要 libpcap/Npcap,也不需要提权。

## Monorepo 开发

npm workspaces + lerna(各包独立版本)。目录结构:

```
packages/
  codec/  pcap-core/  pcap/  analysis/  capture/  iface/  replay/  netkitty/
```

```bash
npm install            # 装依赖,并编译原生插件
npm run build          # 构建每个包(lerna 逐包 tsc)
npm test               # 先构建,再跑各包测试
npm run test:only      # 不重新构建直接跑测试
```

只针对单个包:`npm run build -w @netkitty/codec`、`npm test -w @netkitty/codec`。codec 的测试集包含
字节级往返样本、解码树 golden 快照、tshark 差分对照,以及 schema 模糊测试。

## 许可证

MIT
