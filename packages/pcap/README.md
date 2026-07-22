<p align="center">
  <img src="https://raw.githubusercontent.com/myq1991/netkitty/main/assets/NetKittyLogo.webp" alt="NetKitty" width="180">
</p>

# @netkitty/pcap

Streaming read/write/parse of capture files for Node.js — pcap, pcapng, and classic `.cap`/tcpdump
output, all format-agnostic. `PcapReader` and `PcapWriter` stream over a `node:fs` file handle so a
capture never has to fit in memory, and `PcapReader` can tail a file that is still being written.

> 中文文档见 [README.zh-CN.md](./README.zh-CN.md)。

`PcapParser` is a thin `EventEmitter` shell that pipes a read stream into
[`@netkitty/pcap-core`](../pcap-core) — a pure-buffer, browser-safe parser that does the actual byte
work (magic-number detection, classic pcap in both endiannesses and µs/ns variants, and pcapng).

## Install

```bash
npm i @netkitty/pcap
# or use the aggregate package: import ... from 'netkitty/pcap'
```

## Quick start

### Read a capture

`PcapReader` walks the file and reports one `IPcapPacketInfo` per packet — index, timestamp, and the
byte ranges of the record. Ask for the frame bytes with `readPacketData(info)`; it uses the
`packetOffset`/`packetLength` the parser reported, so the same call works for pcap and pcapng alike.

```ts
import {PcapReader, IPcapPacketInfo} from '@netkitty/pcap'

const reader = new PcapReader({
  filename: '/path/to/capture.pcap',
  onPacket: async (info: IPcapPacketInfo): Promise<void> => {
    const frame: Buffer = await reader.readPacketData(info)   // full frame bytes, pcap or pcapng
    console.log(`#${info.index} @${info.seconds}.${info.microseconds} — ${frame.length} bytes`)
  }
})

reader.on('done', (): void => console.log('reached end of file'))
await reader.start()   // reads to the end, then emits 'done'
```

`onPacket` may be async — the read stream is paused for its duration and resumed afterwards, so
back-pressure is automatic and packets are never dropped while you await. The same information is also
available as the `packet` event if you prefer listeners over the callback.

### Write a capture

`PcapWriter` creates a classic-pcap file (writing the global header up front) or appends to one that
already exists, and streams each frame out with `write()`. Pass the frame bytes and the capture
timestamp split into whole seconds and the sub-second remainder in microseconds. Pass `format: 'pcapng'`
to write pcapng instead (a Section Header + Interface Description block up front, then one Enhanced
Packet Block per frame).

```ts
import {PcapWriter} from '@netkitty/pcap'

const writer = new PcapWriter({filename: '/path/to/out.pcap'})

const now: number = Date.now()
writer.write(frameBytes, Math.floor(now / 1000), (now % 1000) * 1000)

await writer.close()   // flush and close the file handle
```

Each written packet emits a `packet` event carrying the `IPcapPacketInfo` for what landed on disk
(offsets, length, timestamp). `wroteCount` tracks how many frames have been written.

### Tail a growing file

Set `watch: true` and the reader keeps following the file after it hits the current end, picking up
frames as they are appended — pair a `PcapWriter` with a watching `PcapReader` to consume a capture
while it is still being recorded.

```ts
const reader = new PcapReader({filename: '/path/to/growing.pcap', watch: true, onPacket})
await reader.start()   // never resolves to 'done' on its own — stops when you call stop()/close()
await reader.stop()    // or reader.close() to also remove all listeners
```

### Edit a capture

`PcapEdit.rewrite` streams every packet of a capture through a handler and writes the result to a new
file — reading handles pcap/pcapng and gzip/LZ4 transparently, and you choose the output format. The
handler returns one of: nothing (keep), `null`/`false` (drop), a `Buffer` (replace the bytes), a
`{frame?, seconds?, microseconds?}` (change fields), or an array (expand into several packets).

```ts
import {PcapEdit} from '@netkitty/pcap'

const {read, written} = await PcapEdit.rewrite({
  input: 'in.pcapng.gz',                                     // pcap/pcapng, gzip/lz4 — all handled
  output: 'out.pcap',
  onPacket: (frame, info) => {
    if (isNoise(frame)) return null                          // drop
    return {frame: anonymize(frame), seconds: info.seconds - 3600}   // replace bytes + retime
  }
})
```

Common edits are prebuilt as composable transforms — combine them with `PcapEdit.chain(...)`:

```ts
await PcapEdit.rewrite({
  input: 'in.pcap', output: 'out.pcap',
  onPacket: PcapEdit.chain(
    PcapEdit.setSourceMac('00:11:22:33:44:55'),
    PcapEdit.setDestinationMac('aa:bb:cc:dd:ee:ff'),
    PcapEdit.constantInterval(1000),   // space packets 1 ms apart
  )
})
```

- **Retiming:** `shiftTime(seconds, microseconds)`, `setStartTime(seconds, microseconds)`,
  `scaleTime(factor)`, `constantInterval(microseconds)`.
- **Ethernet MAC:** `setSourceMac(mac)`, `setDestinationMac(mac)`, `swapMac()` (assume an Ethernet link layer).
- **`truncate(maxBytes)`** to shorten frames.

For field-aware edits (IP addresses, ports, checksums) decode the frame with
[`@netkitty/codec`](../codec) inside the handler, edit the fields, re-encode, and return the bytes — `pcap`
deliberately stays free of the codec dependency.

`PcapEdit.patchInPlace(file, info, frame)` overwrites one packet's bytes **without rewriting the file** —
valid only when the replacement is the same length as the original packet and the file is uncompressed.

## Key concepts

- **Format-agnostic, detected by content.** The reader does not care whether the file is pcap or pcapng;
  `@netkitty/pcap-core` auto-detects the format from the **magic number** (not the file extension) and
  handles:
  - **classic libpcap** — all four variants: big- and little-endian × microsecond and nanosecond
    timestamps (`a1b2c3d4` / `d4c3b2a1` / `a1b23c4d` / `4d3cb2a1`). This is the format written by tcpdump,
    Wireshark and libpcap, whatever the extension — `.pcap`, `.cap`, `.dump`, or none at all.
  - **pcapng** — section header / interface description / (simple) enhanced packet blocks, with per-interface
    `if_tsresol` timestamp resolution (`0a0d0d0a`).

  Because detection is by content, a mislabelled or extensionless file still parses. Conversely, a `.cap`
  that is *not* libpcap (e.g. a Microsoft Network Monitor capture, a different magic) is **rejected with a
  clear `unknown magic number` error rather than mis-parsed**. `reader.format` exposes the detected
  `PcapFileFormat` (`'pcap' | 'pcapng'`).
- **Transparent decompression.** A capture compressed with **gzip** (`.pcap.gz` / `.pcapng.gz`, magic
  `1f 8b`) or **LZ4** frame format (`.pcap.lz4`, magic `04 22 4d 18`) is decompressed on the fly — the
  reader detects the compression magic, inflates the whole file, and both the streaming parse and
  `readPacketData()` are served from the decompressed bytes, so a compressed capture reads back exactly
  like its plain original. gzip uses Node's built-in `zlib`; LZ4 uses the dependency-free pure-JS
  `Lz4FrameDecompress` from [`@netkitty/pcap-core`](../pcap-core). (zstd is not yet handled; decompress it
  first, e.g. `zstd -d capture.pcapng.zst`.)
- **Read the bytes by info, not by guesswork.** `readPacketData(info)` seeks to the parser-reported
  `packetOffset` and reads exactly `packetLength` bytes, so it is correct for every format. The older
  `readPacket(offset, length)` is **deprecated** — it assumes a fixed 16-byte classic-pcap record header
  and only works for classic files.
- **Streaming throughout.** Reader and writer both stream over a file handle in `chunkSize` reads
  (default `1518 * 10` bytes), so memory stays flat regardless of file size.

## API

### `new PcapReader(options)`

| option      | type                                          | default      | meaning                                             |
| ----------- | --------------------------------------------- | ------------ | --------------------------------------------------- |
| `filename`  | `string`                                      | —            | path to the capture file to read                    |
| `watch`     | `boolean`                                     | `false`      | keep following the file after the current end       |
| `chunkSize` | `number`                                      | `1518 * 10`  | bytes read per file-handle read                     |
| `onPacket`  | `(info: IPcapPacketInfo) => Promise \| void`  | —            | per-packet callback; read is paused while it awaits |
| `onStart`   | `() => Promise \| void`                       | —            | fires when `start()` begins                         |
| `onStop`    | `() => Promise \| void`                       | —            | fires when reading is stopped                       |
| `onDone`    | `() => Promise \| void`                       | —            | fires when the end of the file is reached           |
| `onError`   | `(err: Error) => void`                        | —            | parser/read errors                                  |

- `start(): Promise<void>` — reset and begin reading (straight to the end, or continuously under `watch`).
- `stop(): Promise<void>` — stop reading and tear down the streams.
- `close(): Promise<void>` — stop, then remove all listeners.
- `readPacketData(info: IPcapPacketInfo): Promise<Buffer>` — the full frame bytes for a reported packet.
- `readPacket(offset, length): Promise<Buffer>` — **deprecated**, classic pcap only.
- Events: `packet` (`IPcapPacketInfo`), `start`, `stop`, `done`, `close`, `error`.

### `new PcapWriter(options)`

| option              | type                  | default  | meaning                                                          |
| ------------------- | --------------------- | -------- | ---------------------------------------------------------------- |
| `filename`          | `string`              | —        | output path; created (with header) or appended if it exists      |
| `format`            | `'pcap' \| 'pcapng'`  | `'pcap'` | output format; `'pcapng'` writes SHB + IDB then one EPB per frame |
| `includePacketData` | `boolean`             | `true`   | include the raw bytes as base64 in the emitted `packet` info     |

Set `includePacketData: false` when consumers only need metadata — it skips the per-packet base64
encoding; the bytes are still written to the file.

- `write(packet: Buffer, seconds: number, microseconds: number): void` — append one frame with its timestamp.
- `close(): Promise<void>` — flush and close the file handle.
- `wroteCount: number` — number of frames written so far.
- Events: `packet` (`IPcapPacketInfo`).

### `PcapParser`

The streaming shell used internally by `PcapReader`; you can also drive it directly.

- `PcapParser.parse(input: string | ReadStream): PcapParser` — create a parser over a file path or a read stream.
- `format: PcapFileFormat | null` — the detected format once known.
- Events: `globalHeader`, `sectionHeader`, `packetHeader`, `packetData`, `packet` (`IPcapPacketInfo`),
  `end`, `error`.

### Re-exported from [`@netkitty/pcap-core`](../pcap-core)

`IPcapPacketInfo`, `PcapFileFormat`, the classic-pcap byte generators `GeneratePCAP`,
`GeneratePCAPHeader`, `GeneratePCAPData` (with `GeneratePCAPInputPacket` / `GeneratePCAPPacket`), the
pcapng byte generators `GeneratePcapng`, `GeneratePcapngSectionHeader`,
`GeneratePcapngInterfaceDescription`, `GeneratePcapngEnhancedPacket` (with `GeneratePcapngInputPacket` /
`GeneratePcapngPacket` / `GeneratePcapngOptions`), and the pure-JS `Lz4FrameDecompress` used for
transparent `.lz4` reading.
