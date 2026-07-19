# @netkitty/capture

Live network packet capture built on a native addon over **libpcap (macOS/Linux) / Npcap (Windows)**.
The public `Capture` class **never touches the native binding in the main process**: a shared host
process runs one native capture thread per session and streams every packet back over a named-pipe
IPC channel, so a bad capture — or a crash in native code — can't take your application down with it.
Each packet is also written to a temporary pcap file as it arrives, and `saveTo()` copies that file out.

> 中文文档见 [README.zh-CN.md](./README.zh-CN.md)。

## Install

```bash
npm i @netkitty/capture
# or use the aggregate package: import ... from 'netkitty/network'
```

This package ships a native addon. **No prebuilt binaries are published** — it is compiled from source
on your machine at install time (node-gyp, `gypfile: true`). You therefore need a working C/C++ toolchain
and the pcap development headers:

- **macOS**: Xcode command line tools (libpcap is already present).
- **Linux**: a compiler plus `libpcap-dev` (Debian/Ubuntu) or `libpcap-devel` (RHEL/Fedora).
- **Windows**: [Npcap](https://npcap.com/) installed; the addon loads `wpcap.dll` at runtime, so only the
  headers are needed to build — no `.node`/`.lib` is bundled.

If you only need to list interfaces (no capture, no native build to worry about at runtime), see
[`@netkitty/iface`](../iface).

## Quick start

```ts
import {GetNetworkInterfaces, Capture} from '@netkitty/capture'

// 1. Pick an interface to capture on
const interfaces = GetNetworkInterfaces()          // [{name, mac}, ...] sorted by name
const device = interfaces[0].name

// 2. Create a capture
const capture = new Capture({
    device: device,                                // required: interface name from GetNetworkInterfaces()
    filter: 'tcp port 443',                         // optional: a BPF filter expression
    emit: 'full'                                    // optional: 'full' (default) | 'metadata'
})

// 3. Listen for packets
capture.on('packet', info => {
    console.log(info.index, info.length, info.seconds)   // metadata for every packet
})
capture.on('rawPacket', (index, packet, seconds, microseconds) => {
    // packet: base64-encoded bytes (only fired in 'full' mode)
})
capture.on('error', err => console.error(err))     // host-process crash surfaces here

// 4. Run
await capture.start()
// ... capture for a while ...
await capture.saveTo('/path/to/out.pcap')          // copy the accumulated pcap out
await capture.stop()
await capture.dispose()                            // stop + release the session and temp file
```

## Constructor options (`ICaptureOptions`)

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `device` | `string` | yes | Interface name, as returned by `GetNetworkInterfaces()`. |
| `filter` | `string` | no | BPF filter expression (tcpdump syntax), e.g. `'udp and port 53'`. Empty means capture everything. |
| `emit` | `CaptureEmitMode` | no | `'full'` (default) or `'metadata'` — see below. |
| `tmpDir` | `string` | no | Folder for the temporary pcap file. Defaults to `<os tmpdir>/netkitty-tmp`. |
| `temporaryFilename` | `string` | no | Exact path of the temporary pcap file. Defaults to a name derived from the device and `tmpDir`. |
| `workerModule` | `string` | no | Path to a custom host worker module (advanced; replaces the built-in one and skips device validation). |

## Methods and events

`Capture` extends `EventEmitter`. All lifecycle methods are async and safe to await in sequence:

- `start(): Promise<void>` — begin capturing (resumes if paused).
- `stop(): Promise<void>` — stop capturing and wait for the host to flush every packet seen.
- `pause(): Promise<void>` — stop the native capture but keep the session, so `resume()`/`start()` continue it.
- `resume(): Promise<void>` — continue a paused capture.
- `setFilter(filter: string): Promise<void>` — change the BPF filter (applied live if running, otherwise on next start).
- `saveTo(destination: string): Promise<void>` — copy the accumulated temporary pcap file to `destination`.
- `dispose(): Promise<void>` — stop, tear down the session, and remove the temporary file.

Readonly getters: `filter`, `temporaryFilename`, `count` (packets seen so far).

Events:

- `packet(info: IPcapPacketInfo)` — fires for **every** captured packet, in both emit modes. `info` carries
  `index`, byte `offset`/`length`, the pcap record offsets, and the timestamp (`seconds`/`microseconds`/`nanoseconds`).
- `rawPacket(index: number, packet: string, seconds: number, microseconds: number)` — fires only in
  `'full'` mode; `packet` is the raw bytes, base64-encoded.
- `error(error: Error)` — the host process crashed. It is respawned automatically with every active session
  re-created, so capture continues; this event just lets you know it happened.

## Emit modes (`CaptureEmitMode`)

- **`'full'`** (default) — each packet delivers its metadata **and** its raw bytes (`rawPacket`). Backwards
  compatible, convenient for in-memory decoding.
- **`'metadata'`** — metadata only. The bytes stay in the on-disk pcap file and are **not** sent across the
  IPC boundary, skipping the per-packet base64 encoding and the largest part of the payload. Use this for
  long or high-rate captures where you only need to inspect the file later (via `saveTo()`), and `rawPacket`
  will not fire.

## Architecture

The main process holds only bookkeeping. On first `start()`, a **single shared host process** is forked
(`child_process.fork`, or Electron's `utilityProcess.fork` when running inside Electron) and every `Capture`
registers a session with it, keyed by a unique id. The host drives the native `libpcap`/`Npcap` binding —
one native capture thread per session — writes each packet into that session's temporary pcap file, and
streams the packet back, tagged by session id, over one multiplexed named-pipe channel.

Collapsing many captures into one process (rather than a worker each) is the resource win for multi-interface
capture. If the host process dies unexpectedly, it is respawned and every active session is re-created and
restarted; owners are additionally notified through the `error` event. When the last session is disposed, the
host process is shut down so nothing lingers.

## Platform and privileges

- **macOS/Linux** link against **libpcap**; **Windows** uses **Npcap** (`wpcap.dll`, loaded at runtime).
- Capturing on a live interface usually requires **elevated privileges** — run as `root`/administrator, or
  grant the equivalent capability (e.g. `cap_net_raw` on Linux, or the BPF device permissions / Npcap's
  "restrict to administrators" setting). Interface enumeration and filtering follow the same rules libpcap
  and Npcap apply on your platform.

As a project rule, **netkitty never ships precompiled native binaries**: the addon is always built from
source locally at install time.
