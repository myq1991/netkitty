# Change Log

All notable changes to this project will be documented in this file.
See [Conventional Commits](https://conventionalcommits.org) for commit guidelines.

# [1.2.0](https://github.com/myq1991/netkitty/compare/@netkitty/codec@1.1.0...@netkitty/codec@1.2.0) (2026-07-23)


### Features

* **errors:** add @netkitty/errors — shared NetKittyError base + ErrorCode ([d5a3405](https://github.com/myq1991/netkitty/commit/d5a3405ee1f812ac92ed3d32478c1bece9bdbd89))
* **errors:** route pcap-core/pcap/analysis/replay/capture errors through NetKittyError ([19b0888](https://github.com/myq1991/netkitty/commit/19b08886f490afaeec3620745e545eb2446b4f83))





# 1.1.0 (2026-07-22)


### Bug Fixes

* **codec:** 派发表单例桶也校验 match()，修 IPv4 protocol=0 误路由 ([fc0acef](https://github.com/myq1991/netkitty/commit/fc0acef44c77bdff5d6b6f9a76a5596a5ad6ff0f))


### Features

* **codec:** add ASN.1 ALIGNED BASIC-PER decode engine for CMS ([155636b](https://github.com/myq1991/netkitty/commit/155636bdf887630d73d0cda7b0290351c12e24d4))
* **codec:** add CMS (China smart-substation communication) framing over TCP:8102 ([bb3f5c5](https://github.com/myq1991/netkitty/commit/bb3f5c53d938670a7b40435c9221efeb669434da))
* **codec:** add HTTP/2, WS-Discovery, Megaco, DHCP-Failover, Teredo, BitTorrent, GELF, SLP, Modbus/UDP, Wake-on-LAN, Marker, GE-SRTP, PCWorx, CODESYS, ADS/AMS, BSAP-IP ([1beeb64](https://github.com/myq1991/netkitty/commit/1beeb64863c31f6172c44c125475bd58a4fa821a))
* **codec:** add IEEE 802.3 LLC bearer layer and STP (spanning tree) ([cfe0116](https://github.com/myq1991/netkitty/commit/cfe01166a7338455c6fb771b54a4df1e535551bf))
* **codec:** add ISO Session layer (MMS stack slice 1) above COTP ([ad47440](https://github.com/myq1991/netkitty/commit/ad474404bc8a8c65d265c1bd0795cd608fd4e339))
* **codec:** add MMS layer (Presentation + MMS PDU) — full TPKT/COTP/Session/MMS stack ([7f4db0f](https://github.com/myq1991/netkitty/commit/7f4db0f943544d5afeb53a5077334c98f762d44c))
* **codec:** add RDP X.224 Negotiation over COTP ([192c92b](https://github.com/myq1991/netkitty/commit/192c92b43086831f8ed62d710a95f259de8c46c4))
* **codec:** add SCTP, SMB1, NFS, QUIC, RTP, RTCP ([eb11476](https://github.com/myq1991/netkitty/commit/eb114764d161276b29bad41025a2859afc1e1f3a))
* **codec:** add SLPv1 (Service Location Protocol v1, RFC 2165) ([a64a95c](https://github.com/myq1991/netkitty/commit/a64a95c3a2676f2dab99be880162dc242f9c9378))
* **codec:** add SNAP, CDP and IS-IS over the LLC bearer ([39cce0f](https://github.com/myq1991/netkitty/commit/39cce0f4fbf37181567fd0e61c7d5a0ff8f447de))
* **codec:** add WebSocket (RFC 6455) frame codec (decode-as) ([d5c3703](https://github.com/myq1991/netkitty/commit/d5c3703ef625621002b1043c6d0da53923987e31))
* **codec:** decode plaintext CMS on port 9102 ([251434b](https://github.com/myq1991/netkitty/commit/251434bc7f2c3bfe5cb9fc7559a1b455915f1785))
* **codec:** extract MMS confirmed service and invokeID for display ([ee5737b](https://github.com/myq1991/netkitty/commit/ee5737b380f0b63bb30b3d436140dbf3bb5753cb))
* **codec:** make COTP expose its payload as a child layer; add S7comm (Siemens S7) ([9ffc3bc](https://github.com/myq1991/netkitty/commit/9ffc3bc11f8b98bcd3cfc914ec812a952477338f))
* **codec:** matchKeys 区间语法 + checkConsistency 多 producer 语义 ([562af6c](https://github.com/myq1991/netkitty/commit/562af6c1e97d693a0274714563a180f3b01804f3))
* **codec:** PER decode 64-bit integers exactly and small BIT STRINGs unaligned ([db55e0a](https://github.com/myq1991/netkitty/commit/db55e0ad8f867a15aa91bdd3ba2071889c6a2842))
* **codec:** PER-decode CMS Associate (SC 1) request; name the Test service ([db22428](https://github.com/myq1991/netkitty/commit/db224285bbceeec1566d092966a04ec863f8999b))
* **codec:** PER-decode CMS AssociateNegotiate request and response ([c116568](https://github.com/myq1991/netkitty/commit/c116568ff6efd48c8690d349647796863a6f3cd3))
* **codec:** PER-decode CMS GetAllDataDefinition request service data ([1cc0a8f](https://github.com/myq1991/netkitty/commit/1cc0a8f0392a400c97ecbc2e8c3e8cb5c1c71643))
* **codec:** PER-decode CMS GetAllDataValues (SC 83) request ([a43e37d](https://github.com/myq1991/netkitty/commit/a43e37dadee876284ab37a8f9433743e29ab92fe))
* **codec:** structure CMS per DL/T 2811-2024 (APCH control code, service code, ReqID) ([63e8d06](https://github.com/myq1991/netkitty/commit/63e8d061ed4a27db516884ec325b5f5a5781448e))
* **codec:** surface ACSE AP-titles from the MMS connection phase ([bd8f7b2](https://github.com/myq1991/netkitty/commit/bd8f7b29a0f0cb65d99e78f88fd693492c730c2e))
* **codec:** surface readable identifiers from M-coded CMS responses ([76952e6](https://github.com/myq1991/netkitty/commit/76952e6e46410ec2955348b70a009ac946272df6))
* **codec:** surface the ACSE APDU type from the MMS connection phase ([120f143](https://github.com/myq1991/netkitty/commit/120f1435ec4a56dd45bedde03fd01fd2ac2a74e9))
* **codec:** surface the ACSE application-context OID from the MMS connection phase ([4f6ce55](https://github.com/myq1991/netkitty/commit/4f6ce5529f866e460d9f12337068be242fefcf01))
* **codec:** surface the MMS initiate parameters from the connection phase ([12858b1](https://github.com/myq1991/netkitty/commit/12858b1d0a379aa8712637b968c5c095b8821a92))
* **codec:** surface the object/variable names referenced by an MMS service ([64321e1](https://github.com/myq1991/netkitty/commit/64321e1244c6dfe9457d74b94c87310b9a4cbf6a))
* **codec:** TCP/UDP 端口 demux 维（tcpport/udpport），一致性跳过启发式子层 ([f48cb10](https://github.com/myq1991/netkitty/commit/f48cb109f25698a1a1ef5f15e7026dbcb3c6eb98))
* **codec:** TLS/IEC104 端口桶 dual 注册（443/2404），编辑器菜单按端口出子层 ([3e625b9](https://github.com/myq1991/netkitty/commit/3e625b9622181156cb179c6a1f4d853230bd2245))
* **codec:** 多链路根——decode(packet, linktype?) 按 pcap DLT 选根层 ([8065ee3](https://github.com/myq1991/netkitty/commit/8065ee322c7c4648a539c3db1604c5cd0ee4b079))
* **codec:** 新增 AH、BGP、EAPOL、ESP、Finger、RIP、Rlogin、SOCKS4、WHOIS 九个协议 ([166ff5c](https://github.com/myq1991/netkitty/commit/166ff5c872fd2b2a6ffb5efd5406b84cb3302489))
* **codec:** 新增 BACnet/IP 协议(楼宇自控,udp:47808) ([68437a7](https://github.com/myq1991/netkitty/commit/68437a7b6b537e44922ad4d43a18138a4264ec99))
* **codec:** 新增 BFD Control 协议(RFC 5880) ([25bb165](https://github.com/myq1991/netkitty/commit/25bb165762ddffe3c1fad938196608e81bad9643))
* **codec:** 新增 C37.118 同步相量协议(IEEE C37.118.2,电力 PMU/PDC) ([54e31c3](https://github.com/myq1991/netkitty/commit/54e31c3c636c27871603eb8ca4d255f15855bba1))
* **codec:** 新增 DHCP 协议(RFC 2131)+ fieldIPv4 积木 ([0f555b1](https://github.com/myq1991/netkitty/commit/0f555b1d3e1c5c55b8bc21b315058e8060b0f890))
* **codec:** 新增 DHCPv6 协议(RFC 8415)——option TLV + relay 体原样保留 ([0170f0b](https://github.com/myq1991/netkitty/commit/0170f0b9273a56f110b3643013ac615e41be2bdd))
* **codec:** 新增 Diameter、ISAKMP/IKE、WireGuard 三个协议 ([6d7b16c](https://github.com/myq1991/netkitty/commit/6d7b16cbb209d0a83a142934e255b6212a1cf44a))
* **codec:** 新增 DNP3 协议(IEEE 1815,电力 SCADA,tcp/udp:20000) ([1540d96](https://github.com/myq1991/netkitty/commit/1540d96be0ec592fd4a273a6ba8c673b4cf6558f))
* **codec:** 新增 DNS 协议(RFC 1035)——名字压缩字节完美往返 ([1cd42bc](https://github.com/myq1991/netkitty/commit/1cd42bc08e52feb761cf8667749bf30a0f147bcf))
* **codec:** 新增 EtherNet/IP、CoAP、MQTT 三协议(并行批次:工业以太+IoT) ([3901ae3](https://github.com/myq1991/netkitty/commit/3901ae3ec6362b9be7414c0505eafd75a3c2eeef))
* **codec:** 新增 GENEVE 隧道协议(RFC 8926)+ protocol-type 驱动内层派发 ([a5a50e1](https://github.com/myq1991/netkitty/commit/a5a50e13a1f2ef36260355b0f397c9a8f7b67987))
* **codec:** 新增 GRE 隧道协议(RFC 2784/2890)——首个 IP 层(proto 47)承载协议 ([afe3334](https://github.com/myq1991/netkitty/commit/afe3334791421bfed49eb5b9144669bf3cdc879d))
* **codec:** 新增 GTP-U 隧道协议(3GPP TS 29.281)+ 内层 IP 递归解码 ([36ab54d](https://github.com/myq1991/netkitty/commit/36ab54d1347df6d053022ddb07991ca11865398b))
* **codec:** 新增 HSR、SMTP、POP3 三个协议 ([5f63406](https://github.com/myq1991/netkitty/commit/5f634062345a0a94f08406f634b741f0f849c6e3))
* **codec:** 新增 IGMP、PIM、EIGRP、RSVP、DCCP、PTP、LACP、MPLS、PPPoE、SSDP、GTPv2-C、RIPng、HSRP、SunRPC、Ident 十六个协议 ([dd0c111](https://github.com/myq1991/netkitty/commit/dd0c111b7ca95b2037dc75c2c5b02f688d862386))
* **codec:** 新增 IMAP、NNTP、IRC 三个协议 ([8f40920](https://github.com/myq1991/netkitty/commit/8f40920f6a508eab08bb2f3ad4b89980b5aee0aa))
* **codec:** 新增 L2TP v2 协议(RFC 2661) ([062e478](https://github.com/myq1991/netkitty/commit/062e47878f513ddca3f455049bd0a10ea04b4e14))
* **codec:** 新增 LDAP、Kerberos、Telnet、Memcached、SOCKS5 五个协议 ([ed17c42](https://github.com/myq1991/netkitty/commit/ed17c42b29d47ecd4979128bddbffcd734925bf0))
* **codec:** 新增 LLMNR 协议(RFC 4795)——DNS 报文格式薄子类 ([87a313d](https://github.com/myq1991/netkitty/commit/87a313d203a6603b968bb1f82f7c2ea4c9de7848))
* **codec:** 新增 mDNS 协议(RFC 6762)——DNS 报文格式薄子类 ([5b77926](https://github.com/myq1991/netkitty/commit/5b77926e5bcaf4b7afcc4ac88f2d1c6be5ed2960))
* **codec:** 新增 Modbus/TCP 协议(工业控制,tcp:502) ([9628891](https://github.com/myq1991/netkitty/commit/96288914a4e778740ea8072200bbc8d4e43dcd56))
* **codec:** 新增 NBNS 协议(RFC 1002)——DNS 子类 + NetBIOS first-level 名字编解码 ([99eacb1](https://github.com/myq1991/netkitty/commit/99eacb129a1468210fe8f29b5cdd01dcf2b3de91))
* **codec:** 新增 NetFlow v5、MySQL、PostgreSQL 三个协议 ([27a8cb6](https://github.com/myq1991/netkitty/commit/27a8cb60533551a763507fbac1c1da7b97d62d96))
* **codec:** 新增 NTP 协议(RFC 5905)——打通 M2 全流水线 ([ff5f645](https://github.com/myq1991/netkitty/commit/ff5f6455c6b3b418719a4778e153049d7631a399))
* **codec:** 新增 OPC UA、Redis 两个协议 ([9c95327](https://github.com/myq1991/netkitty/commit/9c95327978422ecd1e80fc28f071471f1571d3ec))
* **codec:** 新增 OpenVPN、DTLS、XMPP、STOMP、LPD、Gopher、NBSS、iSCSI、LDP、PPTP、WCCP、Babel、POWERLINK、Sercos III、HART-IP、FF-HSE 十六个协议 ([4e4ff1e](https://github.com/myq1991/netkitty/commit/4e4ff1eb44fdd2d480484ef20e55aec68a31cb23))
* **codec:** 新增 OSPFv2 协议(RFC 2328) ([410265e](https://github.com/myq1991/netkitty/commit/410265ecc9324d67e857d9ff611010dcf57614c4))
* **codec:** 新增 PROFINET-RT、EtherCAT、HTTP 三个协议 ([2266267](https://github.com/myq1991/netkitty/commit/2266267285f11b0362cebe9fa852c85e6e7f45c6))
* **codec:** 新增 R-GOOSE/R-SV（IEC 61850-90-5 会话层）Slice 1 ([2534603](https://github.com/myq1991/netkitty/commit/2534603f43dd63c519c7947a5c272be8bce6ef84))
* **codec:** 新增 RADIUS 协议(RFC 2865/2866)——20 字节固定头 + AVP TLV ([263e4aa](https://github.com/myq1991/netkitty/commit/263e4aa8c500cc5d5a5bf43f7edd65410f699a47))
* **codec:** 新增 RMCP/ASF 协议(ASF 2.0 DSP0136 / IPMI 2.0) ([7e1a04f](https://github.com/myq1991/netkitty/commit/7e1a04fee199d2fbee56e60c5bb24abf899f35de))
* **codec:** 新增 sFlow v5、AMQP、Kafka、VNC/RFB、SSH 五个协议(首个大批次) ([d27cad6](https://github.com/myq1991/netkitty/commit/d27cad64e131aeb820aa6eda5eafdcd074c82698))
* **codec:** 新增 SMB2、SMPP、MongoDB、Cassandra CQL、OpenFlow、Git、CAPWAP、LISP、RTPS、OMRON FINS、KNXnet/IP、SLMP、MQTT-SN、NBDS、rsync 十五个协议 ([2708b3d](https://github.com/myq1991/netkitty/commit/2708b3d4c02ffe26079b27cc1ca555786754379f))
* **codec:** 新增 SNMP 协议(RFC 1157/3416,v1/v2c)——手写最小 BER 编解码 ([9c42b59](https://github.com/myq1991/netkitty/commit/9c42b597ffface935a56553b0654a21f67280ef3))
* **codec:** 新增 STUN 协议(RFC 5389)——通用 TLV 属性 + 内容签名匹配 ([87780ac](https://github.com/myq1991/netkitty/commit/87780acc07951c3e0f653100083ab00d9a163e15))
* **codec:** 新增 Syslog 协议(RFC 3164/5424)——<PRI>+文本轻结构化 ([66227fe](https://github.com/myq1991/netkitty/commit/66227fec360ed981d80e70664b32b9eff9af8a61))
* **codec:** 新增 TACACS+、LLDP、SIP 三个协议 ([3a2ea87](https://github.com/myq1991/netkitty/commit/3a2ea87bbe1fd3fe331f29dddd300b34de59a4f6))
* **codec:** 新增 TFTP 协议(RFC 1350/2347)——全 opcode + 端口 69 边界守卫 ([2733880](https://github.com/myq1991/netkitty/commit/27338803c177867570b1836922b8ea13cbf88da1))
* **codec:** 新增 TPKT+COTP、FTP、RTSP 三组协议 ([783b3fd](https://github.com/myq1991/netkitty/commit/783b3fd4b09b4b00db41fc45f1b0f610ce9c3236))
* **codec:** 新增 VRRP 协议(v2 RFC 3768 / v3 RFC 5798) ([65da4c8](https://github.com/myq1991/netkitty/commit/65da4c8961f651f7fce970bdf1a56baa23fa8034))
* **codec:** 新增 VXLAN 协议(RFC 7348)——首个隧道协议,内层以太帧递归解码 ([f3eaf53](https://github.com/myq1991/netkitty/commit/f3eaf53df9d341f9feaec67f14cad9383bc0bbbf))
* **codec:** 新增 Zabbix、StatsD、collectd、Elasticsearch、NATS、MGCP、Skinny、IAX2、GLBP、OLSR、NHRP、IPFIX、OPC UA PubSub、MACsec、Time、FCoE 十六个协议 ([a78b647](https://github.com/myq1991/netkitty/commit/a78b647f1f5f2a85943422d52a61849625f993cc))
* **codec:** 派发支持双层登记（demux 桶 + heuristic 兜底）与确定性优先级 ([9b46233](https://github.com/myq1991/netkitty/commit/9b46233ca4f485237ecd3969a1a1f5b682909e71))
* **monorepo:** 阶段1a 迁移 @netkitty/codec(含 helper+schema) ([4abc60e](https://github.com/myq1991/netkitty/commit/4abc60e03e587c6ee913921e673686958c55d4a8))
* **monorepo:** 阶段3 聚合 netkitty 包 + subpath 兼容 + 根转 workspace root ([6eca06c](https://github.com/myq1991/netkitty/commit/6eca06c8d49148d3494abca74721d3ea65843e0b))


### Performance Improvements

* **codec:** amortize encode buffer growth (doubling + logical length) ([ddbfab0](https://github.com/myq1991/netkitty/commit/ddbfab060aeb3675061e9f695cc4afcbd4a8a375))
* **codec:** resolve encode header constructor via id-to-ctor map ([acfe922](https://github.com/myq1991/netkitty/commit/acfe922a614962505e49b4ca7f5c6bf6ece83c8b))





# Changelog

All notable changes to this package are documented here, following
[Semantic Versioning](https://semver.org/). From the next release onward, entries
are generated automatically from Conventional Commits.

## 1.0.0 - 2026-07-22

First stable release.

- Schema-driven encode/decode of 188 protocol headers — from Ethernet/IP/TCP/UDP
  and the mainstream application layer through a deep bench of industrial/OT
  protocols (Modbus, DNP3, IEC 104, IEC 61850 GOOSE/SV/MMS, S7comm, OPC UA,
  PROFINET, EtherCAT, EtherNet/IP, BACnet and more).
- One executable JSON Schema per header doubles as field tree, byte codec, Ajv
  validator and UI form metadata. Decode never throws; errors accumulate on a
  field-path-addressed list.
