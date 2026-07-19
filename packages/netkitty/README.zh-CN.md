# netkitty

网络工具集的聚合包——一个包就把整个 netkitty 家族通过稳定的子路径重新导出:schema 驱动的协议
**编解码(codec)**、**pcap**/pcapng 的读写与解析、流式的跨包**分析(analysis)**、实时**抓包
(capture)**、**网卡(iface)**信息枚举,以及数据包**重放(replay)**与打流量。装一个 `netkitty`,就能用
`netkitty/*` 触达每一个子系统,不用逐个包去装配,而且原有的 import 全部照旧,老用户零破坏。

> English docs: [README.md](./README.md)

每个子路径都只是对应 `@netkitty/*` 子包的一层薄薄的再导出,所以你既可以只依赖 `netkitty` 这一个总包,
也可以直接依赖各个独立子包——两种写法拿到的符号完全一样。

## 安装

```bash
npm i netkitty
```

## 子路径一览

| 从这里导入 | 对应子包 | 提供什么 |
| --- | --- | --- |
| `netkitty/codec` | [`@netkitty/codec`](../codec) | schema 驱动的 `Codec`——把字节解码成各层协议,再编码回字节 |
| `netkitty/codec/header` | [`@netkitty/codec`](../codec) | 内置的协议头类(Ethernet、IPv4/6、TCP/UDP、ARP、TLS、GOOSE/SV、IEC 104 等) |
| `netkitty/helper` | [`@netkitty/codec`](../codec) | 协议头编解码用到的 Buffer / Hex / Number / IP / BER 转换 helper |
| `netkitty/pcap` | [`@netkitty/pcap`](../pcap) + [`@netkitty/pcap-core`](../pcap-core) | 流式的 `PcapReader`/`PcapWriter`,以及 pcap/pcapng 解析器(`PcapParser`,外加浏览器安全的 `PcapParserCore`) |
| `netkitty/analysis` | [`@netkitty/analysis`](../analysis) | `Analysis`——对抓包文件做流式的跨包分析(会话、端点、TCP 流) |
| `netkitty/network` | [`@netkitty/capture`](../capture) | 基于 libpcap/Npcap 的实时抓包 |
| `netkitty/iface` | [`@netkitty/iface`](../iface) | 只读地枚举本机网卡、地址和收发统计 |
| `netkitty/replay` | [`@netkitty/replay`](../replay) | 按录制的时序(或指定速率)重放 pcap/pcapng/cap,以及打流量 |

这套映射是稳定的:`netkitty/codec`、`netkitty/codec/header` 和 `netkitty/helper` 都落到
`@netkitty/codec`(分别是编解码器本身、它的协议头类、它的转换 helper);其余每个子路径各自对应一个子包。
每个子路径背后子包的完整 API,点上面的链接查看。

## 示例

用 `netkitty/codec` 解码一个包:

```ts
import {Codec, HexToBuffer} from 'netkitty/codec'

const codec = new Codec()
const layers = await codec.decode(HexToBuffer('ffffffffffff0011223344550806...'))

layers[0].id     // 'eth'
layers[0].data   // {dmac: 'ff:ff:ff:ff:ff:ff', smac: '00:11:22:33:44:55', etherType: '0806'}

const {packet} = await codec.encode(layers)   // 解出来的各层直接编码回去,还原原始字节
```

用 `netkitty/pcap` 读一个抓包文件:

```ts
import {PcapReader, IPcapPacketInfo} from 'netkitty/pcap'

const reader = new PcapReader({
  filename: '/path/to/capture.pcap',
  onPacket: async (info: IPcapPacketInfo): Promise<void> => {
    const frame: Buffer = await reader.readPacketData(info)   // pcap 或 pcapng,同一个调用
    console.log(`#${info.index} — ${frame.length} bytes`)
  }
})
await reader.start()
```

用 `netkitty/analysis` 分析一个抓包文件:

```ts
import {Analysis} from 'netkitty/analysis'

const analysis = new Analysis()
await analysis.open('/path/to/capture.pcap')   // 在工作线程里给整个文件建索引
const conversations = await analysis.conversations()
await analysis.close()
```

## 原生子路径与纯 TypeScript 子路径

- **原生子路径**——`netkitty/network`(`@netkitty/capture`)、`netkitty/iface` 和 `netkitty/replay`
  ——都带有原生插件。项目**绝不发布预编译二进制**:插件会在安装时用 `node-gyp` 在你本机从源码编译,所以
  你需要一套可用的 C/C++ 工具链(抓包和重放还需要 macOS/Linux 上的 libpcap,或 Windows 上的 Npcap)。
  这几个子路径仅限 Node.js。
- **纯 TypeScript 子路径**——`netkitty/codec`、`netkitty/codec/header` 和 `netkitty/helper`
  (`@netkitty/codec`),以及 `netkitty/pcap` 内部的解析核心(`@netkitty/pcap-core`)——只处理内存里的
  字节,可以在 **Node 和浏览器**里原样运行。`netkitty/analysis` 同样两端都能跑(重活放在工作线程里做)。
  `netkitty/pcap` 的流式 `PcapReader`/`PcapWriter` 依赖 `node:fs`,仅限 Node.js,但它底层的
  `PcapParserCore` 是浏览器安全的。
