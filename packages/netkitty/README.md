<p align="center">
  <img src="https://raw.githubusercontent.com/myq1991/netkitty/main/assets/NetKittyLogo.webp" alt="NetKitty" width="180">
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/netkitty"><img src="https://img.shields.io/npm/v/netkitty?style=flat-square&labelColor=162032&color=2979ff&logo=npm&logoColor=white" alt="npm version"></a>
  <a href="https://www.npmjs.com/package/netkitty"><img src="https://img.shields.io/npm/dm/netkitty?style=flat-square&labelColor=162032&color=22c55e&logo=npm&logoColor=white" alt="npm downloads"></a>
  <a href="https://github.com/myq1991/netkitty/blob/main/LICENSE"><img src="https://img.shields.io/npm/l/netkitty?style=flat-square&labelColor=162032&color=2979ff" alt="license"></a>
</p>

# netkitty

The aggregate network toolkit — one package that re-exports the whole netkitty family through stable
subpaths: schema-driven protocol **codec**, **pcap**/pcapng read/write/parse, streaming cross-packet
**analysis**, live packet **capture**, network **interface** discovery, and packet **replay** / traffic
generation. Install `netkitty` and reach every subsystem via `netkitty/*` — no per-package wiring, and
existing imports keep working unchanged.

> 中文文档见 [README.zh-CN.md](./README.zh-CN.md)。

Each subpath is a thin re-export of a focused `@netkitty/*` package, so you can depend on the single
`netkitty` umbrella or on the individual packages — the symbols are identical either way.

## Install

```bash
npm i netkitty
```

## Subpaths

| Import from | Backed by | What it gives you |
| --- | --- | --- |
| `netkitty/codec` | [`@netkitty/codec`](../codec) | schema-driven `Codec` — decode bytes into protocol layers and encode them back |
| `netkitty/pcap` | [`@netkitty/pcap`](../pcap) + [`@netkitty/pcap-core`](../pcap-core) | streaming `PcapReader`/`PcapWriter` and the pcap/pcapng parser (`PcapParser`, plus the browser-safe `PcapParserCore`) |
| `netkitty/analysis` | [`@netkitty/analysis`](../analysis) | `Analysis` — streaming, cross-packet analysis over a capture file (conversations, endpoints, TCP streams) |
| `netkitty/capture` | [`@netkitty/capture`](../capture) | live packet capture over libpcap/Npcap |
| `netkitty/iface` | [`@netkitty/iface`](../iface) | read-only enumeration of host network interfaces, addresses and tx/rx stats |
| `netkitty/replay` | [`@netkitty/replay`](../replay) | replay pcap/pcapng/cap at recorded timing (or a target rate) and generate traffic |

The mapping is stable: `netkitty/codec` re-exports the whole `@netkitty/codec` package (the Codec
engine, the built-in header classes, and the conversion helpers); the other subpaths each front a
single package. Follow a link above for the full API of the package behind each subpath.

## Examples

Decode a packet through `netkitty/codec`:

```ts
import {Codec, HexToBuffer} from 'netkitty/codec'

const codec = new Codec()
const layers = await codec.decode(HexToBuffer('ffffffffffff0011223344550806...'))

layers[0].id     // 'eth'
layers[0].data   // {dmac: 'ff:ff:ff:ff:ff:ff', smac: '00:11:22:33:44:55', etherType: '0806'}

const {packet} = await codec.encode(layers)   // decoded layers re-emit the original bytes
```

Read a capture file through `netkitty/pcap`:

```ts
import {PcapReader, IPcapPacketInfo} from 'netkitty/pcap'

const reader = new PcapReader({
  filename: '/path/to/capture.pcap',
  onPacket: async (info: IPcapPacketInfo): Promise<void> => {
    const frame: Buffer = await reader.readPacketData(info)   // pcap or pcapng, same call
    console.log(`#${info.index} — ${frame.length} bytes`)
  }
})
await reader.start()
```

Analyse a capture through `netkitty/analysis`:

```ts
import {Analysis} from 'netkitty/analysis'

const analysis = new Analysis()
await analysis.open('/path/to/capture.pcap')   // index the file in a worker
const conversations = await analysis.conversations()
await analysis.close()
```

## Native versus pure-TypeScript subpaths

- **Native subpaths** — `netkitty/capture` (`@netkitty/capture`), `netkitty/iface` and `netkitty/replay`
  — ship a native addon. There are **no prebuilt binaries**: the addon is compiled from source on your
  machine at install time via `node-gyp`, so you need a working C/C++ toolchain (and, for capture/replay,
  libpcap on macOS/Linux or Npcap on Windows). These subpaths are Node.js only.
- **Pure-TypeScript subpaths** — `netkitty/codec`
  (`@netkitty/codec`) and the parser core inside `netkitty/pcap` (`@netkitty/pcap-core`) — touch nothing
  but in-memory buffers and run unchanged in **node and the browser**. `netkitty/analysis` runs in both
  environments too (it does the heavy work in a worker). `netkitty/pcap`'s streaming `PcapReader`/
  `PcapWriter` use `node:fs` and are Node.js only, but the underlying `PcapParserCore` is browser-safe.
