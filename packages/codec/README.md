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
#   protocol header classes live under netkitty/codec/header, helpers under netkitty/helper
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

| id             | name                                       |
| -------------- | ------------------------------------------ |
| `eth`            | Ethernet II                                          |
| `vlan`           | 802.1Q Virtual LAN                                   |
| `arp`            | Address Resolution Protocol                          |
| `ipv4`           | Internet Protocol Version 4                          |
| `ipv6`           | Internet Protocol Version 6                          |
| `ipv6-hopopt`    | IPv6 Hop-by-Hop Option                               |
| `icmp`           | Internet Control Message Protocol                    |
| `icmpv6`         | Internet Control Message Protocol v6                 |
| `tcp`            | Transmission Control Protocol                        |
| `udp`            | User Datagram Protocol                               |
| `tls-handshake`  | Transport Layer Security (Handshake Protocol)        |
| `tls-alert`      | Transport Layer Security (Alert Protocol)            |
| `tls-ccsp`       | Transport Layer Security (ChangeCipherSpec Protocol) |
| `tls-appdata`    | Transport Layer Security (Application Data Protocol)  |
| `tls-heartbeat`  | Transport Layer Security (Heartbeat Protocol)        |
| `goose`          | IEC61850 GOOSE                                        |
| `sv`             | IEC61850 Sampled Values                              |
| `IEC104_I_Frame` | IEC 60870-5-104 (I frame)                            |
| `IEC104_S_Frame` | IEC 60870-5-104 (S frame)                            |
| `IEC104_U_Frame` | IEC 60870-5-104 (U frame)                            |
| `raw`            | Raw Data (the forced catch-all)                      |

## License

MIT
