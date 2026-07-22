<p align="center">
  <img src="https://raw.githubusercontent.com/myq1991/netkitty/main/assets/NetKittyLogo.webp" alt="NetKitty" width="180">
</p>

# NetKitty

A network toolkit for Node.js (and the browser, where it can be): live packet capture, pcap/pcapng
reading and writing, a schema-driven protocol codec that both **decodes and encodes** packet headers,
streaming cross-packet analysis, read-only interface enumeration, and packet replay / traffic
generation. Ships as one aggregate package (`netkitty`) over a workspaces monorepo of focused
`@netkitty/*` packages you can also install on their own.

> 中文文档见 [README.zh-CN.md](./README.zh-CN.md)。

## Packages

| Package | Import via | What it does | Runtime |
| --- | --- | --- | --- |
| [`@netkitty/codec`](./packages/codec) | `netkitty/codec` | Schema-driven encode/decode of 188 packet headers — Ethernet/VLAN/ARP, IPv4/6, TCP/UDP/SCTP, TLS, DNS/DHCP/HTTP, and industrial/OT protocols (GOOSE/SV, IEC 104, Modbus, DNP3, S7comm, MMS, CMS, …) | node + browser |
| [`@netkitty/pcap-core`](./packages/pcap-core) | (core of `netkitty/pcap`) | Pure-buffer pcap/pcapng parsing and generation, no Node deps | node + browser |
| [`@netkitty/pcap`](./packages/pcap) | `netkitty/pcap` | Node streaming pcap/pcapng read / write / parse | node |
| [`@netkitty/analysis`](./packages/analysis) | `netkitty/analysis` | Streaming, Wireshark-style cross-packet analysis over a worker | node + browser |
| [`@netkitty/capture`](./packages/capture) | `netkitty/capture` | Live capture over libpcap/Npcap (native addon) | node |
| [`@netkitty/iface`](./packages/iface) | `netkitty/iface` | Read-only interface enumeration, addresses and tx/rx stats (native addon) | node |
| [`@netkitty/replay`](./packages/replay) | `netkitty/replay` | Replay pcap at recorded timing, or generate traffic (native addon) | node |
| [`netkitty`](./packages/netkitty) | — | Aggregate package re-exporting all of the above by subpath | node |

## Install

```bash
# everything, one dependency:
npm i netkitty

# or a single focused package:
npm i @netkitty/codec
```

The pure-TypeScript packages (`codec`, `pcap-core`, `analysis`) are browser-safe. The native packages
(`capture`, `iface`, `replay`) build a native addon from source at install time — see
[Native addons](#native-addons--platforms) below.

## Quick start

Decode and re-encode a packet — decoding produces a valid encode input, so the two are symmetric:

```ts
import {Codec, HexToBuffer} from 'netkitty/codec'

const codec = new Codec()
const layers = await codec.decode(HexToBuffer('ffffffffffff0011223344550806...'))
// layers[0] => {id: 'eth', name: 'Ethernet II', data: {dmac, smac, etherType}, errors: []}

const {packet} = await codec.encode(layers) // rebuild the original bytes
```

Read a capture file (pcap or pcapng, transparently):

```ts
import {PcapReader, IPcapPacketInfo} from 'netkitty/pcap'

const reader = new PcapReader({
  filename: 'capture.pcap',
  onPacket: async (info: IPcapPacketInfo): Promise<void> => {
    const frame: Buffer = await reader.readPacketData(info)
    console.log(`#${info.index} — ${frame.length} bytes`)
  }
})
await reader.start()
```

Replay a capture at its recorded timing (or generate traffic with `mode: 'topspeed'`):

```ts
import {replayFile} from 'netkitty/replay'

const replay = await replayFile('capture.pcap', {device: 'en0'})
replay.on('done', (s) => console.log(`sent ${s.sent} frames on ${s.backend}`))
replay.start()
```

Each package's README has the full API and more examples.

## Design philosophy (the codec)

The codec is architected backwards from a GUI packet editor — a *programmable Wireshark* — not from a
high-throughput dissector. Every protocol header is **one executable JSON Schema** that plays four
roles at once: the field-tree structure, the per-field `decode`/`encode` closures, Ajv input
validation (`useDefaults` makes the schema double as a packet template, `coerceTypes` tolerates form
input), and UI form metadata (`label`, `hidden`, `contentEncoding`, `enum`/`const` discriminators). A
`JSON.parse(JSON.stringify())` round-trip strips the closures, giving a serializable schema a frontend
can render as an editable form — the boundary between the declarative shell and the imperative core.

Two consequences worth knowing:

- **Decode never fails.** Layer dispatch is an O(1) demux table (`ethertype:` / `ipproto:` keys) with a
  `RawData` catch-all, so unknown or malformed bytes always decode to a best-effort result plus a
  field-path-addressed error list — never an exception.
- **You can build invalid packets on purpose.** Errors accumulate (they don't throw) and `encode` is a
  faithful executor, not a semantic judge — so it will emit exactly the (even illegal) layers and field
  values you give it. This makes the library usable for negative / malformed-packet testing, and every
  decode→encode round-trip is byte-exact.

See [`@netkitty/codec`](./packages/codec) for the full treatment. Deliberate non-goals: line-rate
throughput (per-field async closures) and cross-packet reassembly (the codec is single-packet;
reassembly belongs a layer above it).

## Native addons & platforms

netkitty **never ships prebuilt binaries.** The native packages (`capture`, `iface`, `replay`) compile
their addon from source on your machine at install time (via node-gyp), so you need a working C/C++
toolchain:

- **macOS**: Xcode Command Line Tools (libpcap is bundled).
- **Linux**: a compiler plus `libpcap-dev` (Debian/Ubuntu) or `libpcap-devel` (RHEL/Fedora).
- **Windows**: install [Npcap](https://npcap.com/); the addon loads `wpcap.dll` at runtime, so only
  headers are needed to build — no `.dll`/`.lib`/`.node` is bundled.

Capturing and sending packets generally require elevated privileges (root/Administrator, or an
equivalent capability such as `cap_net_raw` on Linux). `@netkitty/iface` is the exception: it uses only
OS APIs, needs no libpcap/Npcap, and no special privileges.

## Monorepo development

npm workspaces + lerna (independent versioning). Layout:

```
packages/
  codec/  pcap-core/  pcap/  analysis/  capture/  iface/  replay/  netkitty/
```

```bash
npm install            # install deps and compile the native addons
npm run build          # build every package (lerna → tsc per package)
npm test               # build then run each package's tests
npm run test:only      # run tests without rebuilding
```

A single package: `npm run build -w @netkitty/codec`, `npm test -w @netkitty/codec`. The codec test
suite includes byte-exact round-trip fixtures, decode-tree goldens, a tshark differential oracle, and
schema fuzzing.

## License

MIT
