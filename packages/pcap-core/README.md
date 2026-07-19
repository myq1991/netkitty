# @netkitty/pcap-core

A pure-buffer pcap/pcapng parsing state machine and generator — **zero node dependencies,
browser-safe** (Buffer only, no `node:fs`/`events`/`node:util`). It delivers results through
**injected callbacks instead of an EventEmitter**: you construct it with a handler bag, feed it bytes
with `write(chunk)`, and it drains its state machine synchronously, calling you back for each header
and packet.

> 中文文档见 [README.zh-CN.md](./README.zh-CN.md)。

This is the low-level core. For streaming reads on node (backed by `node:fs`, an EventEmitter API,
random access), use [`@netkitty/pcap`](../pcap); for cross-packet, Wireshark-style analysis, use
[`@netkitty/analysis`](../analysis). Reach for `@netkitty/pcap-core` directly when you already hold the
bytes (a browser `File`/`Blob`, a WebSocket chunk, an in-memory capture) and just want them parsed.

## Install

```bash
npm i @netkitty/pcap-core
```

## Quick start — parse

Construct a `PcapParserCore` with the callbacks you care about, then push bytes in. Chunks may arrive
in any size — the parser buffers partial records and only calls `onPacket` once a full packet is
available, so streaming a file in 64 KB pieces yields exactly the same result as one big `write`.

```ts
import {PcapParserCore, IPcapPacketInfo} from '@netkitty/pcap-core'

const parser = new PcapParserCore({
  onGlobalHeader: header => console.log('classic pcap header', header),   // classic pcap only
  onSectionHeader: header => console.log('pcapng section', header),       // pcapng only
  onPacket: (info: IPcapPacketInfo) => {
    console.log(info.index, info.seconds, info.microseconds, info.nanoseconds)
    console.log(info.packet)   // captured bytes, base64
  },
  onEnd: () => console.log('done'),
  onError: err => console.error('corrupt capture:', err.message)
})

// feed bytes in any chunking; the parser detects pcap vs pcapng by magic number
parser.write(someBuffer)
parser.write(moreBuffer)
parser.end()

parser.format   // 'pcap' | 'pcapng' | null — resolved after the first bytes arrive
```

Every packet is reported as an `IPcapPacketInfo`:

```ts
interface IPcapPacketInfo {
  index: number               // 1-based packet counter
  offset: number              // byte offset of this record/block in the file
  length: number              // total record/block length in bytes
  recordHeaderOffset: number  // byte offset of the record/block header
  recordHeaderLength: number  // header length before the packet data
  packetOffset: number        // byte offset of the captured packet data
  packetLength: number        // captured packet length in bytes
  seconds: number             // timestamp — whole seconds
  microseconds: number        // sub-second fraction, microseconds (0..999_999)
  nanoseconds: number         // sub-second fraction, nanoseconds (0..999_999_999)
  packet: string              // captured packet bytes, base64
}
```

The other handlers are optional and map one-to-one onto the parser's stages: `onGlobalHeader`
(classic pcap 24-byte global header), `onSectionHeader` (pcapng section header block), `onPacketHeader`
(the per-packet record header, normalized across both formats), and `onPacketData` (the raw captured
`Buffer`, delivered just before `onPacket`).

## Quick start — generate

`GeneratePCAP` turns a list of base64 frames into a complete classic pcap file buffer (Ethernet
link-layer by default). Use the piecewise `GeneratePCAPHeader` / `GeneratePCAPData` when you want to
stream records out one at a time.

```ts
import {GeneratePCAP, GeneratePCAPHeader, GeneratePCAPData} from '@netkitty/pcap-core'

// whole file in one call
const file: Buffer = GeneratePCAP([
  {frameBase64Data: base64Frame, timestamp: Date.now()},                       // timestamp in ms
  {frameBase64Data: base64Frame, microsecond: {seconds: 1_700_000_000, microseconds: 123_456}}
])

// or assemble it yourself, record by record
const chunks: Buffer[] = [GeneratePCAPHeader()]
chunks.push(GeneratePCAPData({buffer: rawFrame, timestamp: Date.now()}))
const alsoAFile: Buffer = Buffer.concat(chunks)
```

`GeneratePCAP` accepts `frameBase64Data` plus either a `timestamp` (milliseconds) or an explicit
`microsecond: {seconds, microseconds}`; `GeneratePCAPData` takes the same but with a raw `buffer`
instead of base64. The output round-trips: feed it back into `PcapParserCore` and you get your frames
returned.

## Key concepts

- **Format is auto-detected by magic number.** Classic libpcap (`.pcap`/`.cap`/tcpdump output) is
  recognized in all four variants — big- and little-endian, microsecond and nanosecond — and pcapng by
  its section header block. You never tell the parser which format you have; `parser.format` reports
  what it found once the first four bytes are in.
- **Full nanosecond precision, everywhere.** Classic nanosecond captures keep their `nanoseconds`
  intact, and pcapng honors each interface's `if_tsresol` option (base-10 or base-2 tick resolution),
  converting 64-bit timestamps down to whole seconds plus a full nanosecond fraction. `seconds`,
  `microseconds`, and `nanoseconds` are always populated so a consumer can pick whatever precision it
  needs.
- **Robust against corrupt input — bounded memory, no throws.** Captured lengths and pcapng block
  lengths are sanity-checked against Wireshark's limits, so a malformed length field can't make the
  parser allocate wildly or spin. On a bad file it stops and reports through `onError` (never a thrown
  exception), and unknown or obsolete pcapng blocks (name resolution, interface statistics, custom
  blocks) are skipped rather than fatal.

## Formats supported

- Classic pcap 2.x, both endiannesses, microsecond and nanosecond timestamp variants
- pcapng: Section Header (SHB), Interface Description (IDB, including `if_tsresol`), Enhanced Packet
  (EPB), Simple Packet (SPB), obsolete Packet Block; other block types are skipped

Generation currently emits classic pcap 2.4.
