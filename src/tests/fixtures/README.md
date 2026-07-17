# Test Fixtures

## packets/ — 单包 hex 样本

每个 `.hex` 文件格式：`#` 开头的行是注释（描述 + 来源），最后一行是完整以太网帧的 hex 字符串。
全部由本地 `pcaps/` 目录（不入库）中的真实抓包经 tshark 提取，来源标注在各文件第二行注释中。

| 目录 | 内容 | 用途 |
| --- | --- | --- |
| `goose/` | 纯 GOOSE、VLAN+GOOSE（含 Structure 数据项） | GOOSE 编解码基线 |
| `sv/` | IEC 61850-9-2 采样值帧 | SV 编解码基线 |
| `iec104/` | I 帧（带 ASDU）、S 帧、U 帧（TESTFR act / STARTDT con） | IEC104 基线；STARTDT con 为解码大小写 bug 回归样本 |
| `vlan/` | 802.1Q 承载 GOOSE | VLAN 标签编解码 |
| `arp/` | ARP 请求帧 | ARP 基线 |
| `ipv4/` | 带 CIPSO 选项的头（IHL>5）、首片/后续分片 | IPv4 变长头与分片边界 |
| `ipv6/` | 纯 IPv6+TCP、Hop-by-Hop 扩展头+ICMPv6、Segment Routing 扩展头 | IPv6 与扩展头；ipv6/tcp 为 IPv6 上 TCP match bug 回归样本 |
| `icmp/` `icmpv6/` | echo request/reply、ICMPv6 | 校验和与类型字段 |
| `tcp/` | 纯 TCP 段、TCP+HTTP 载荷 | TCP 基线 |
| `udp/` | 普通 UDP、NetBIOS UDP | UDP 基线 |
| `tls/` | TLS 1.2 record | TLS record 层基线 |
| `codec/` | 未知 ethertype 0x88b5 巨帧 | 未知协议落 RawData 的兜底行为 |

## 异常/边界样本约定

畸形报文（截断、非法字段值、错误长度）**不存文件**，由测试代码基于正常样本程序化构造（截断 buffer、翻转字段等），
这样每个畸形用例与其基线的差异在代码中一目了然。

## 提取方法

`tshark -r <pcap> -Y <filter> -T jsonraw` 取 `frame_raw`。
提取脚本参见维护者本地 scratchpad（`extract-fixtures.sh`），新增协议样本时按同样格式追加即可。
