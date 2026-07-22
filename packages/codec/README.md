<p align="center">
  <img src="https://raw.githubusercontent.com/myq1991/netkitty/main/assets/NetKittyLogo.webp" alt="NetKitty" width="180">
</p>

# @netkitty/codec

Schema-driven protocol codec for encoding and decoding packet headers — Ethernet, IPv4/6, TCP/UDP,
ARP, TLS, GOOSE/SV (IEC 61850), IEC 104 and more. Every header is one **executable JSON Schema** that
is at once the field tree, the byte-level codec, the input validator, and the form metadata a UI needs.
It is designed backwards from a GUI packet editor — a programmable Wireshark — rather than a
throughput dissector. Pure TypeScript, no native dependencies: it only ever touches an in-memory
`Buffer`, so it runs unchanged in **node and the browser**.

> 中文文档见 [README.zh-CN.md](./README.zh-CN.md)。

## Install

```bash
npm i @netkitty/codec
# or use the aggregate package: import {Codec} from 'netkitty/codec'
#   protocol header classes and conversion helpers are all re-exported from netkitty/codec
```

## Quick start

Decode turns raw bytes into an ordered list of protocol layers; encode turns layers back into bytes.
A decoded result is itself a valid encode input, so the two are exact mirrors (read → edit → re-emit).

```ts
import {Codec, HexToBuffer} from '@netkitty/codec'

const codec = new Codec()

// Decode: Buffer → layered result (outermost layer first)
const packet = HexToBuffer('ffffffffffff0011223344550806...')
const layers = await codec.decode(packet)

layers[0]        // {id: 'eth', name: 'Ethernet II', nickname: 'ETH', protocol: true, errors: [], data: {...}}
layers[0].data   // {dmac: 'ff:ff:ff:ff:ff:ff', smac: '00:11:22:33:44:55', etherType: '0806'}
layers[0].errors // [] — per-field errors accumulate here, decode never throws

// Encode: layers → Buffer. Feed the decoded layers straight back to re-emit the packet.
const {packet: rebuilt, errors} = await codec.encode(layers)
rebuilt.equals(packet)   // true for a well-formed packet — decode/encode round-trip exactly
```

Build a packet from scratch by handing `encode` an array of `{id, data}` inputs in outer-to-inner
order; any field you omit is filled from the schema's defaults, and form-string values are coerced:

```ts
const {packet} = await codec.encode([
  {id: 'eth', data: {dmac: 'ff:ff:ff:ff:ff:ff', smac: '00:11:22:33:44:55', etherType: '0800'}},
  {id: 'ipv4', data: {sip: '192.168.0.1', dip: '192.168.0.2', protocol: 17}},
  {id: 'udp', data: {srcport: 12345, dstport: 53}}
])
```

### Signatures

```ts
class Codec {
  constructor(customCodecs?: CodecModuleConstructor[])           // override/extend built-in headers
  decode(packet: Buffer): Promise<CodecDecodeResult[]>
  encode(inputs: CodecEncodeInput[]): Promise<CodecEncodeResult>
}

type CodecDecodeResult = {
  id: string                 // protocol id, e.g. 'eth', 'ipv4', 'tcp'
  name: string               // human-readable name, e.g. 'Ethernet II'
  nickname: string           // short tag, e.g. 'ETH'
  protocol: boolean          // whether this layer is a real protocol (false for raw payload)
  errors: CodecErrorInfo[]   // {id, path, message}[] — field-path-addressed decode errors
  data: HeaderTreeNode       // the decoded field tree
}

type CodecEncodeInput  = Pick<CodecDecodeResult, 'id' | 'data'> & Partial<Omit<CodecDecodeResult, 'id' | 'data'>>
type CodecEncodeResult = {packet: Buffer, errors: CodecErrorInfo[]}
```

## Key concepts

### One executable schema, four roles

Each header extends `BaseHeader` and declares a single `SCHEMA` (a `ProtocolJSONSchema`). That one
declaration plays four parts at once:

1. **Field-tree structure** — the shape of the decoded/encoded data.
2. **Codec logic** — every field embeds `decode`/`encode` closures that read and write the shared
   packet buffer through `this.readBytes/writeBytes` and `this.readBits/writeBits` (offsets are
   header-relative; the buffer auto-expands on write, so nothing needs a length pre-pass). Values live
   on `this.instance`, a `FlexibleObject` — a path-tracking proxy whose deep access never throws and
   yields exact dotted field paths (`options[3].kind`) for binding errors to UI inputs.
3. **Input validation** — `encode` validates each input with Ajv against the schema. `useDefaults`
   makes the schema double as a packet template (omitted fields are filled in); `coerceTypes` tolerates
   form-string input.
4. **UI form metadata** — custom keywords (`label`, `hidden`, `contentEncoding`) plus `enum`/`min`/`max`
   and `anyOf` + `const` discriminators describe how a form should render each field.

### Decode never fails; errors accumulate instead of throwing

Malformed packets are first-class input. A field whose bytes are truncated or invalid records an error
via `recordError()` (a `{id, path, message}` entry on the layer's `errors`) and clamps to a best-effort
value — it does not throw. Decode therefore always returns a full best-effort layer list plus a
field-path-addressed error list you can use to highlight problems in a UI. The only deliberate fast-fail
is the Ajv shape check at the `encode` entry point.

### RawData is the catch-all

Decode walks the packet and, for each layer, selects the first header whose demux value or content
heuristic matches at the current offset, then advances and recurses until the packet is consumed.
`RawData` is the forced final fallback and always matches, so unknown or malformed trailing bytes simply
become a `raw` layer and decode can never dead-end.

### The declarative shell vs. the imperative core

`PROTOCOL_SCHEMA` is the schema with its closures stripped (via a `JSON.parse(JSON.stringify())`
round-trip — JSON serialization dropping functions is the deliberate boundary). What remains is pure,
serializable JSON Schema you can ship to a frontend to drive a form; the byte offsets, bit fields and
TLV/BER parsing stay behind in the closures. When you add a field, keep that split: anything a form
needs must be serializable schema, anything procedural belongs in the closures.

### Cross-layer fixups run as post-handlers

Length fields and checksums depend on bytes another layer only finalizes later. Headers register
post-encode/decode handlers with priorities for these fixups; packet-level post-encode handlers run
last-in-first-out (outer layers depend on inner layers' final bytes), post-decode handlers run
first-in-first-out (inner semantics depend on outer context, e.g. TCP's checksum needs the IPv4
addresses).

### Custom and additional headers

`new Codec(customCodecs)` takes an array of header classes. A custom class replaces the built-in with
the same `PROTOCOL_ID`; a class with a new id is appended. To add a brand-new built-in protocol,
implement a `BaseHeader` subclass and register it in `PacketHeaders.ts` (and re-export it from the
package's entry point).

### Editor helpers

Alongside `decode`/`encode`, `Codec` exposes read-only projections over the same decode for building an
editor UI: `dissect(packet)` returns a field tree annotated with each field's exact byte span, label and
error/ok severity (a Wireshark-style hex-to-field view); `summary(decoded)` renders a one-line
description (Wireshark's Info column); `allowedNextLayers`, `childDiscriminator` and `checkConsistency`
describe and validate which layer may follow which.

## Built-in headers

188 protocol headers are registered by default; `raw` is the forced catch-all. Pass custom classes to `new Codec(customCodecs)` to override a built-in with the same id or add new ones.

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

## License

MIT
