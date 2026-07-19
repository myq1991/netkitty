# @netkitty/codec

schema 驱动的协议编解码器,负责把报文各层协议头在字节和结构之间来回转换——涵盖 Ethernet、IPv4/6、
TCP/UDP、ARP、TLS、GOOSE/SV(IEC 61850)、IEC 104 等。每一个协议头都是一份**可执行的 JSON Schema**,
同一份声明同时充当字段树、字节级编解码逻辑、输入校验器,以及界面所需的表单元数据。它的设计取向是从一个
图形化的报文编辑器(可编程的 Wireshark)倒推出来的,而不是追求吞吐的解析器。纯 TypeScript,不依赖任何
原生模块:全程只操作内存里的 `Buffer`,因此**在 Node 和浏览器里都能原样运行**。

> English docs: [README.md](./README.md)

## 安装

```bash
npm i @netkitty/codec
# 或者用聚合包:import {Codec} from 'netkitty/codec'
#   协议头类在 netkitty/codec/header 下,helper 函数在 netkitty/helper 下
```

## 快速上手

解码把原始字节变成一列有序的协议层,编码则把协议层还原成字节。解码得到的结果本身就是一份合法的编码输入,
所以两者是严格互逆的(读取 → 修改 → 重新生成)。

```ts
import {Codec, HexToBuffer} from '@netkitty/codec'

const codec = new Codec()

// 解码:Buffer → 分层结果(最外层在前)
const packet = HexToBuffer('ffffffffffff0011223344550806...')
const layers = await codec.decode(packet)

layers[0]        // {id: 'eth', name: 'Ethernet II', nickname: 'ETH', protocol: true, errors: [], data: {...}}
layers[0].data   // {dmac: 'ff:ff:ff:ff:ff:ff', smac: '00:11:22:33:44:55', etherType: '0806'}
layers[0].errors // [] —— 逐字段的错误累积在这里,解码永远不会抛异常

// 编码:分层结果 → Buffer。把解码得到的各层直接喂回去,就能重新生成这个报文。
const {packet: rebuilt, errors} = await codec.encode(layers)
rebuilt.equals(packet)   // 对于结构完好的报文为 true —— 解码/编码严格往返一致
```

想从零构造一个报文,只要按从外到内的顺序给 `encode` 传一组 `{id, data}` 输入即可;没填的字段会用
schema 里的默认值补齐,表单传来的字符串也会被自动转换成对应类型:

```ts
const {packet} = await codec.encode([
  {id: 'eth', data: {dmac: 'ff:ff:ff:ff:ff:ff', smac: '00:11:22:33:44:55', etherType: '0800'}},
  {id: 'ipv4', data: {sip: '192.168.0.1', dip: '192.168.0.2', protocol: 17}},
  {id: 'udp', data: {srcport: 12345, dstport: 53}}
])
```

### 方法签名

```ts
class Codec {
  constructor(customCodecs?: CodecModuleConstructor[])           // 覆盖或扩展内置协议头
  decode(packet: Buffer): Promise<CodecDecodeResult[]>
  encode(inputs: CodecEncodeInput[]): Promise<CodecEncodeResult>
}

type CodecDecodeResult = {
  id: string                 // 协议 id,如 'eth'、'ipv4'、'tcp'
  name: string               // 可读名称,如 'Ethernet II'
  nickname: string           // 简称,如 'ETH'
  protocol: boolean          // 该层是否为真正的协议(原始载荷为 false)
  errors: CodecErrorInfo[]   // {id, path, message}[] —— 用字段路径定位的解码错误
  data: HeaderTreeNode       // 解码出来的字段树
}

type CodecEncodeInput  = Pick<CodecDecodeResult, 'id' | 'data'> & Partial<Omit<CodecDecodeResult, 'id' | 'data'>>
type CodecEncodeResult = {packet: Buffer, errors: CodecErrorInfo[]}
```

## 关键概念

### 一份可执行 schema,四重身份

每个协议头都继承 `BaseHeader`,并声明一份 `SCHEMA`(即 `ProtocolJSONSchema`)。这一份声明同时扮演
四个角色:

1. **字段树结构**——决定解码/编码后数据的形状。
2. **编解码逻辑**——每个字段内嵌 `decode`/`encode` 闭包,通过 `this.readBytes/writeBytes` 和
   `this.readBits/writeBits` 读写共享的报文缓冲区(偏移量都相对于当前协议头;写入时缓冲区会自动扩容,
   因此无需预先计算长度)。字段值存放在 `this.instance` 上,它是一个 `FlexibleObject`——一个会记录
   路径的代理对象,深层访问永远不会抛异常,并能给出精确的点分字段路径(如 `options[3].kind`),用来把
   错误绑定到界面上对应的输入框。
3. **输入校验**——`encode` 会用 Ajv 按 schema 校验每一份输入。`useDefaults` 让 schema 同时充当报文
   模板(缺失字段自动补齐);`coerceTypes` 则容忍来自表单的字符串输入。
4. **界面表单元数据**——自定义关键字(`label`、`hidden`、`contentEncoding`),加上 `enum`/`min`/`max`
   以及 `anyOf` + `const` 判别式,共同描述表单该如何渲染每个字段。

### 解码永不失败,错误只累积不抛出

畸形报文本身就是合法输入。某个字段的字节被截断或取值非法时,会通过 `recordError()` 记录一条错误(即该
层 `errors` 上的一条 `{id, path, message}`),并把值收敛到一个尽力而为的结果——而不是抛异常。因此解码
总能返回一份完整的、尽力而为的分层结果,外加一份用字段路径定位的错误清单,供界面高亮问题。唯一刻意的
快速失败,是 `encode` 入口处的 Ajv 形状校验。

### RawData 兜底

解码会遍历整个报文,对每一层在当前偏移处选出第一个 demux 值或内容特征匹配的协议头,解出后前移偏移并
递归,直到把报文消费完。`RawData` 是被强制放在最后的兜底项,且永远匹配成功,所以无法识别或畸形的尾部
字节会直接变成一层 `raw`,解码绝不会走进死胡同。

### 声明式外壳与命令式内核

`PROTOCOL_SCHEMA` 是剥离了闭包之后的 schema(通过 `JSON.parse(JSON.stringify())` 往返——JSON 序列化
会丢弃函数,这正是刻意划出的边界)。剥离后剩下的是纯粹、可序列化的 JSON Schema,可以直接下发给前端去
驱动表单;而字节偏移、位字段、TLV/BER 解析这些则留在闭包里。新增字段时请守住这条分界:表单需要的东西
必须是可序列化的 schema,过程性的东西一律放进闭包。

### 跨层修正走 post handler

长度字段和校验和往往依赖其他层稍后才最终确定的字节。协议头会为这类修正注册带优先级的 post
encode/decode 处理器;报文级的 post encode 处理器按后进先出执行(外层依赖内层最终生成的字节),post
decode 处理器按先进先出执行(内层语义依赖外层上下文,例如 TCP 校验和需要 IPv4 的地址)。

### 自定义与新增协议头

`new Codec(customCodecs)` 接受一组协议头类。自定义类会替换掉 `PROTOCOL_ID` 相同的内置协议头;id 全新
的类则被追加进来。若要新增一个内置协议,实现一个 `BaseHeader` 子类,并在 `PacketHeaders.ts` 中注册
(同时从包的入口文件里重新导出)。

### 编辑器辅助方法

除 `decode`/`encode` 之外,`Codec` 还在同一次解码之上提供若干只读投影,用来搭建编辑器界面:
`dissect(packet)` 返回一棵字段树,每个字段都标注了它占据的精确字节区间、标签,以及错误/正常的严重级别
(类似 Wireshark 的字节到字段视图);`summary(decoded)` 渲染出一行描述(相当于 Wireshark 的 Info 列);
`allowedNextLayers`、`childDiscriminator` 和 `checkConsistency` 则描述并校验哪一层可以接在哪一层之后。

## 内置协议头

| id               | 名称                                                  |
| ---------------- | ----------------------------------------------------- |
| `eth`            | Ethernet II                                           |
| `vlan`           | 802.1Q Virtual LAN                                    |
| `arp`            | Address Resolution Protocol                           |
| `ipv4`           | Internet Protocol Version 4                           |
| `ipv6`           | Internet Protocol Version 6                           |
| `ipv6-hopopt`    | IPv6 Hop-by-Hop Option                                |
| `icmp`           | Internet Control Message Protocol                     |
| `icmpv6`         | Internet Control Message Protocol v6                  |
| `tcp`            | Transmission Control Protocol                         |
| `udp`            | User Datagram Protocol                                |
| `tls-handshake`  | Transport Layer Security(Handshake Protocol)          |
| `tls-alert`      | Transport Layer Security(Alert Protocol)              |
| `tls-ccsp`       | Transport Layer Security(ChangeCipherSpec Protocol)   |
| `tls-appdata`    | Transport Layer Security(Application Data Protocol)    |
| `tls-heartbeat`  | Transport Layer Security(Heartbeat Protocol)          |
| `goose`          | IEC61850 GOOSE                                         |
| `sv`             | IEC61850 Sampled Values                               |
| `IEC104_I_Frame` | IEC 60870-5-104(I 帧)                                 |
| `IEC104_S_Frame` | IEC 60870-5-104(S 帧)                                 |
| `IEC104_U_Frame` | IEC 60870-5-104(U 帧)                                 |
| `raw`            | Raw Data(强制兜底的原始数据)                          |

## 许可证

MIT
