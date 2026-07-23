<p align="center">
  <img src="https://raw.githubusercontent.com/myq1991/netkitty/main/assets/NetKittyLogo.webp" alt="NetKitty" width="180">
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/@netkitty/codec"><img src="https://img.shields.io/npm/v/@netkitty/codec?style=flat-square&labelColor=162032&color=2979ff&logo=npm&logoColor=white" alt="npm version"></a>
  <a href="https://www.npmjs.com/package/@netkitty/codec"><img src="https://img.shields.io/npm/dm/@netkitty/codec?style=flat-square&labelColor=162032&color=22c55e&logo=npm&logoColor=white" alt="npm downloads"></a>
  <a href="https://github.com/myq1991/netkitty/blob/main/LICENSE"><img src="https://img.shields.io/npm/l/@netkitty/codec?style=flat-square&labelColor=162032&color=2979ff" alt="license"></a>
</p>

# @netkitty/codec

schema 驱动的协议编解码器,负责把报文各层协议头在字节和结构之间来回转换——覆盖**189 种协议**,贯穿整个
协议栈。每一个协议头都是一份**可执行的 JSON Schema**,
同一份声明同时充当字段树、字节级编解码逻辑、输入校验器,以及界面所需的表单元数据。它的设计取向是从一个
图形化的报文编辑器(可编程的 Wireshark)倒推出来的,而不是追求吞吐的解析器。纯 TypeScript,不依赖任何
原生模块:全程只操作内存里的 `Buffer`,因此**在 Node 和浏览器里都能原样运行**。

**协议覆盖**贯穿链路层与网络层(Ethernet、VLAN/802.1Q、ARP、IPv4/IPv6、ICMP/ICMPv6、MPLS、GRE、VXLAN、
GENEVE)、传输层(TCP、UDP、SCTP、DCCP、QUIC),以及主流应用层(HTTP、HTTP/2、TLS/DTLS、DNS/mDNS、
DHCP/DHCPv6、MQTT/MQTT-SN、CoAP、AMQP、Kafka、MongoDB、MySQL、PostgreSQL、Redis、SSH、LDAP、Kerberos、
SNMP、NTP、PTP、SIP/RTP/RTCP、RTSP、SMB、NFS、RADIUS、Diameter、WireGuard、GTP)。而它真正的差异化在于一整套
**工业 / OT / SCADA** 协议:Modbus(TCP/UDP)、DNP3、IEC 104、IEC 61850(GOOSE、Sampled Values、MMS、
R-GOOSE)、S7comm、OPC UA(含 PubSub)、PROFINET RT、EtherCAT、EtherNet/IP、BACnet/IP、POWERLINK、
HART-IP、Omron FINS、SLMP、CODESYS、C37.118、SercosIII、GE-SRTP。

> English docs: [README.md](./README.md)

## 安装

```bash
npm i @netkitty/codec
# 或者用聚合包:import {Codec} from 'netkitty/codec'
#   协议头类和转换 helper 都从 netkitty/codec 一并导出
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

默认注册了 189 个协议头(`raw` 是强制兜底)。向 `new Codec(customCodecs)` 传入自定义类可覆盖同 id 的内置头或新增协议头。

| id               | name                                                |
| ---------------- | --------------------------------------------------- |
| `adsams`         | Beckhoff ADS/AMS                                    |
| `ah`             | IP Authentication Header                            |
| `amqp`           | AMQP 0-9-1                                          |
| `arp`            | Address Resolution Protocol                         |
| `babel`          | Babel Routing Protocol                              |
| `bacnet`         | BACnet/IP                                           |
| `bfd`            | Bidirectional Forwarding Detection                  |
| `bgp`            | Border Gateway Protocol                             |
| `bittorrent`     | BitTorrent Peer Wire Protocol                       |
| `bsap`           | Bristol/Emerson BSAP over IP                        |
| `c37118`         | IEEE C37.118 Synchrophasor                          |
| `capwap`         | Control And Provisioning of Wireless Access Points  |
| `cdp`            | Cisco Discovery Protocol                            |
| `cms`            | CMS (China Substation Communication, DL/T 2811)     |
| `coap`           | Constrained Application Protocol                    |
| `codesys`        | CODESYS V3                                          |
| `collectd`       | collectd Network Protocol                           |
| `cotp`           | COTP                                                |
| `cql`            | Cassandra CQL                                       |
| `dccp`           | Datagram Congestion Control Protocol                |
| `dhcp`           | Dynamic Host Configuration Protocol                 |
| `dhcpfo`         | DHCP Failover                                       |
| `dhcpv6`         | Dynamic Host Configuration Protocol for IPv6        |
| `diameter`       | Diameter                                            |
| `dnp3`           | Distributed Network Protocol 3                      |
| `dns`            | Domain Name System                                  |
| `dtls`           | Datagram Transport Layer Security                   |
| `eapol`          | EAP over LAN                                        |
| `ecat`           | EtherCAT                                            |
| `eigrp`          | Enhanced Interior Gateway Routing Protocol          |
| `elasticsearch`  | Elasticsearch Transport                             |
| `enip`           | EtherNet/IP                                         |
| `esp`            | IP Encapsulating Security Payload                   |
| `eth`            | Ethernet II                                         |
| `fcoe`           | Fibre Channel over Ethernet                         |
| `ffhse`          | FOUNDATION Fieldbus HSE                             |
| `finger`         | Finger                                              |
| `fins`           | OMRON FINS                                          |
| `ftp`            | File Transfer Protocol                              |
| `gelf`           | Graylog Extended Log Format                         |
| `geneve`         | Generic Network Virtualization Encapsulation        |
| `gesrtp`         | GE-SRTP                                             |
| `git`            | Git Smart Protocol                                  |
| `glbp`           | Gateway Load Balancing Protocol                     |
| `goose`          | IEC61850 GOOSE                                      |
| `gopher`         | Internet Gopher Protocol                            |
| `gre`            | Generic Routing Encapsulation                       |
| `gtp`            | GPRS Tunnelling Protocol, User plane                |
| `gtpv2`          | GPRS Tunnelling Protocol version 2, Control plane   |
| `hartip`         | HART-IP                                             |
| `hsr`            | High-availability Seamless Redundancy               |
| `hsrp`           | Hot Standby Router Protocol                         |
| `http`           | Hypertext Transfer Protocol                         |
| `http2`          | Hypertext Transfer Protocol 2                       |
| `iax2`           | Inter-Asterisk eXchange v2                          |
| `icmp`           | Internet Control Message Protocol                   |
| `icmpv6`         | Internet Control Message Protocol v6                |
| `ident`          | Identification Protocol                             |
| `IEC104_I_Frame` | IEC 60870-5-104                                     |
| `IEC104_S_Frame` | IEC 60870-5-104                                     |
| `IEC104_U_Frame` | IEC 60870-5-104                                     |
| `igmp`           | Internet Group Management Protocol                  |
| `imap`           | Internet Message Access Protocol                    |
| `ipfix`          | IP Flow Information Export                          |
| `ipv4`           | Internet Protocol Version 4                         |
| `ipv6`           | Internet Protocol Version 6                         |
| `ipv6-hopopt`    | IPv6 Hop-by-Hop Option                              |
| `irc`            | Internet Relay Chat                                 |
| `isakmp`         | ISAKMP/IKE                                          |
| `iscsi`          | Internet Small Computer Systems Interface           |
| `isis`           | Intermediate System to Intermediate System          |
| `iso-session`    | ISO Session                                         |
| `kafka`          | Kafka                                               |
| `kerberos`       | Kerberos                                            |
| `knxnetip`       | KNXnet/IP                                           |
| `l2tp`           | Layer Two Tunneling Protocol                        |
| `lacp`           | Link Aggregation Control Protocol                   |
| `ldap`           | LDAP                                                |
| `ldp`            | Label Distribution Protocol                         |
| `lisp`           | Locator/ID Separation Protocol                      |
| `llc`            | Logical Link Control                                |
| `lldp`           | Link Layer Discovery Protocol                       |
| `llmnr`          | Link-Local Multicast Name Resolution                |
| `lpd`            | Line Printer Daemon Protocol                        |
| `macsec`         | MAC Security                                        |
| `marker`         | Link Aggregation Marker Protocol                    |
| `mdns`           | Multicast DNS                                       |
| `megaco`         | Media Gateway Control Protocol (H.248/Megaco)       |
| `memcached`      | Memcached                                           |
| `mgcp`           | Media Gateway Control Protocol                      |
| `mms`            | Manufacturing Message Specification                 |
| `modbus`         | Modbus/TCP                                          |
| `modbusudp`      | Modbus/UDP                                          |
| `mongodb`        | MongoDB Wire Protocol                               |
| `mpls`           | Multiprotocol Label Switching                       |
| `mqtt`           | MQTT                                                |
| `mqttsn`         | MQTT for Sensor Networks                            |
| `mysql`          | MySQL Protocol                                      |
| `nats`           | NATS Client Protocol                                |
| `nbds`           | NetBIOS Datagram Service                            |
| `nbns`           | NetBIOS Name Service                                |
| `nbss`           | NetBIOS Session Service                             |
| `netflow5`       | NetFlow v5                                          |
| `nfs`            | Network File System                                 |
| `nhrp`           | NBMA Next Hop Resolution Protocol                   |
| `nntp`           | Network News Transfer Protocol                      |
| `ntp`            | Network Time Protocol                               |
| `olsr`           | Optimized Link State Routing                        |
| `opcua`          | OPC UA Connection Protocol                          |
| `opcua-pubsub`   | OPC UA PubSub                                       |
| `openflow`       | OpenFlow                                            |
| `openvpn`        | OpenVPN Protocol                                    |
| `ospf`           | Open Shortest Path First                            |
| `pcworx`         | PCWorx                                              |
| `pgsql`          | PostgreSQL Protocol                                 |
| `pim`            | Protocol Independent Multicast                      |
| `pnio`           | PROFINET Real-Time                                  |
| `pop3`           | Post Office Protocol v3                             |
| `powerlink`      | Ethernet POWERLINK                                  |
| `pppoe-disc`     | PPP-over-Ethernet Discovery                         |
| `pppoe-sess`     | PPP-over-Ethernet Session                           |
| `pptp`           | Point-to-Point Tunnelling Protocol                  |
| `ptp`            | Precision Time Protocol                             |
| `quic`           | QUIC Transport                                      |
| `r-session`      | IEC 61850-90-5 Session                              |
| `radius`         | Remote Authentication Dial-In User Service          |
| `raw`            | Raw Data                                            |
| `rdp`            | Remote Desktop Protocol                             |
| `redis`          | Redis Serialization Protocol                        |
| `rfb`            | RFB (VNC)                                           |
| `rip`            | Routing Information Protocol                        |
| `ripng`          | RIP for IPv6                                        |
| `rlogin`         | Rlogin                                              |
| `rmcp`           | Remote Management Control Protocol                  |
| `rsvp`           | Resource ReSerVation Protocol                       |
| `rsync`          | Rsync Daemon Protocol                               |
| `rtcp`           | RTP Control Protocol                                |
| `rtp`            | Real-time Transport Protocol                        |
| `rtps`           | Real-Time Publish-Subscribe Wire Protocol           |
| `rtsp`           | Real Time Streaming Protocol                        |
| `s7comm`         | S7 Communication                                    |
| `sctp`           | Stream Control Transmission Protocol                |
| `sercos3`        | Sercos III                                          |
| `sflow`          | sFlow v5                                            |
| `sip`            | Session Initiation Protocol                         |
| `skinny`         | Skinny Client Control Protocol                      |
| `slmp`           | SeamLess Message Protocol                           |
| `slp`            | Service Location Protocol                           |
| `slpv1`          | Service Location Protocol Version 1                 |
| `smb1`           | SMB1                                                |
| `smb2`           | SMB2                                                |
| `smpp`           | Short Message Peer-to-Peer                          |
| `smtp`           | Simple Mail Transfer Protocol                       |
| `snap`           | Sub-Network Access Protocol                         |
| `snmp`           | Simple Network Management Protocol                  |
| `socks4`         | SOCKS4                                              |
| `socks5`         | SOCKS5                                              |
| `ssdp`           | Simple Service Discovery Protocol                   |
| `ssh`            | SSH                                                 |
| `statsd`         | StatsD Metrics Protocol                             |
| `stomp`          | Simple Text Oriented Messaging Protocol             |
| `stp`            | Spanning Tree Protocol                              |
| `stun`           | Session Traversal Utilities for NAT                 |
| `sunrpc`         | ONC RPC                                             |
| `sv`             | IEC61850 Sampled Values                             |
| `syslog`         | Syslog                                              |
| `tacacs`         | TACACS+                                             |
| `tcp`            | Transmission Control Protocol                       |
| `telnet`         | Telnet                                              |
| `teredo`         | Teredo IPv6 over UDP tunneling                      |
| `tftp`           | Trivial File Transfer Protocol                      |
| `timeproto`      | Time Protocol                                       |
| `tls-alert`      | Transport Layer Security(Alert Protocol)            |
| `tls-appdata`    | Transport Layer Security(Application Data Protocol) |
| `tls-ccsp`       | Transport Layer Security(ChangeCipherSpec Protocol) |
| `tls-handshake`  | Transport Layer Security(Handshake Protocol)        |
| `tls-heartbeat`  | Transport Layer Security(Heartbeat Protocol)        |
| `tpkt`           | TPKT                                                |
| `udp`            | User Datagram Protocol                              |
| `vlan`           | 802.1Q Virtual LAN                                  |
| `vrrp`           | Virtual Router Redundancy Protocol                  |
| `vxlan`          | Virtual eXtensible Local Area Network               |
| `wccp`           | Web Cache Communication Protocol                    |
| `whois`          | WHOIS                                               |
| `wireguard`      | WireGuard                                           |
| `wol`            | Wake-on-LAN                                         |
| `wsdiscovery`    | Web Services Dynamic Discovery                      |
| `xmpp`           | Extensible Messaging and Presence Protocol          |
| `zabbix`         | Zabbix Protocol                                     |

## 许可证

MIT
