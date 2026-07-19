# @netkitty/replay

Packet replay and traffic generation over a native addon — send frames out a real interface either to
**faithfully reproduce recorded timing** (accurate replay) or to **hold a target rate** (traffic
generation). It picks the fastest send backend the platform offers (Linux TX_RING / PF_PACKET,
BSD/macOS BPF, Windows Npcap), and the whole send loop runs on a **dedicated native thread**, so the
Node event loop is never blocked — progress, completion and errors come back as events.

> 中文文档见 [README.zh-CN.md](./README.zh-CN.md)。

Timestamps for accurate replay come from [`@netkitty/pcap`](../pcap), which parses each frame's
`seconds`/`nanoseconds` out of pcap/pcapng/cap files.

## Install

```bash
npm i @netkitty/replay
# or use the aggregate package: import ... from 'netkitty/replay'
```

The native addon is compiled from source at install time with node-gyp — **no prebuilt binaries are
ever shipped**. You need a working C/C++ toolchain plus the pcap development headers: `libpcap-dev`
(Linux) / the libpcap headers (BSD/macOS ship them) / [Npcap](https://npcap.com) with its SDK
(Windows). Sending packets generally needs elevated privileges (root, `CAP_NET_RAW`, an admin shell,
or membership in a bpf group), so run your program accordingly.

Interface names can be discovered with [`@netkitty/iface`](../iface)'s `list()`.

## Quick start

### Accurate replay of a capture file

Reproduce the exact inter-frame timing recorded in the file:

```ts
import {replayFile} from '@netkitty/replay'

const replay = await replayFile('capture.pcap', {device: 'en0'})   // default mode: multiplier, rate 1
replay.on('progress', (s) => console.log(`${s.sent} frames, ${s.mbps.toFixed(1)} Mbps`))
replay.on('done', (s) => console.log(`done on ${s.backend}: ${s.sent} sent, ${s.failed} failed`))
replay.on('error', (e) => console.error(e))
replay.start()
```

`replayFile` loads the whole capture into memory and returns a `Replay` that is **not yet started** —
attach your listeners first, then call `start()`.

### Traffic generation

Send a set of frames as fast as the interface accepts, no pacing:

```ts
import {Replay, loadFrames} from '@netkitty/replay'

const replay = new Replay({device: 'eth0', mode: 'topspeed'})
replay.addFrames(await loadFrames('capture.pcap'))   // or build frames yourself
replay.on('done', (s) => console.log(s))
replay.start()
```

Frames are just Layer-2 bytes, so you can synthesise them directly (edit them with
[`@netkitty/codec`](../codec) beforehand if you like):

```ts
const replay = new Replay({device: 'eth0', mode: 'pps', rate: 10000})
replay.addFrames([{data: myFrameBuffer}])            // timestamp omitted — ignored outside multiplier
replay.start()
```

### Helpers

- `loadFrames(file)` reads a pcap/pcapng/cap file (any endianness, µs or ns resolution) fully into
  memory as `IReplayFrame[]`, preserving each frame's timestamp for `multiplier` mode.
- `isSendAvailable()` probes whether the pcap send path can be opened. On Windows it loads `wpcap.dll`
  and returns `false` when Npcap is not installed — mainly a Windows readiness check (the native
  PF_PACKET/BPF backends on POSIX do not need it). Never throws.

## Frames

```ts
interface IReplayFrame {
  data: Buffer          // the complete Layer-2 frame, sent verbatim
  seconds?: number      // capture timestamp — only consulted in multiplier mode
  nanoseconds?: number  // sub-second part of the timestamp
}
```

In `topspeed`, `mbps` and `pps` modes the timestamp is ignored, so a raw traffic generator can omit it.

## Options

`new Replay(options)` / `replayFile(file, options)` — every field of `IReplayOptions`:

| Option | Type | Default | Meaning |
| --- | --- | --- | --- |
| `device` | `string` | *(required)* | Interface to transmit on (`en0` / `eth0` / an Npcap device string). |
| `mode` | `ReplayMode` | `'multiplier'` | Pacing mode — see below. |
| `rate` | `number` | `1` | The mode's rate: multiplier factor / megabits-per-second / packets-per-second. |
| `loop` | `number` | `1` | Number of passes over the frame set. |
| `infinite` | `boolean` | `false` | Loop forever (overrides `loop`). |
| `loopDelayMs` | `number` | `0` | Pause between passes, in milliseconds. |
| `limit` | `number` | `0` | Stop after this many frames have been sent (`0` = no limit). |
| `maxSleepMs` | `number` | `0` | Clamp any single inter-frame wait to at most this many ms (`0` = no clamp) — handy to skip long idle gaps in a recording. |
| `precision` | `ReplayPrecision` | `'auto'` | Timing precision for paced modes — see below. |
| `realtime` | `boolean` | `false` | Request real-time scheduling for the send thread. |
| `cpu` | `number \| 'auto'` | *(unpinned)* | Pin the send thread to a CPU core to cut pacing jitter. |
| `validateDevice` | `boolean` | `true` | Verify the device exists before starting. |

### Modes (`mode` + `rate`)

- **`multiplier`** — reproduce the recorded inter-frame timing, scaled by `rate`: `1` = original
  speed, `2` = twice as fast, `0.5` = half speed. This is accurate replay, and the only mode that reads
  frame timestamps.
- **`topspeed`** — send as fast as the interface accepts, no pacing (`rate` ignored). Traffic
  generation.
- **`mbps`** — hold an average throughput of `rate` megabits per second.
- **`pps`** — hold an average rate of `rate` packets per second.

### Precision (`precision`, paced modes only)

- **`auto`** (default) — sleep the bulk of each gap, then busy-spin the final ~250µs for accuracy.
- **`sleep`** — always sleep: lower CPU, coarser timing.
- **`spin`** — busy-spin more aggressively: highest accuracy, highest CPU.

### Jitter and scheduling (`realtime`, `cpu`)

A safe priority boost is always applied to the send thread. Beyond that:

- **`realtime`** requests real-time scheduling (POSIX `SCHED_FIFO` / Windows `TIME_CRITICAL`) for the
  tightest possible pacing. It needs elevated privileges to take effect and can monopolise a CPU core —
  leave it off unless you need it.
- **`cpu`** pins the send thread to one core so the scheduler stops migrating it, which reduces jitter.
  A **number** pins to that 0-based core; **`'auto'`** picks the highest core in the process's allowed
  set (skips core 0, respects any `taskset`/cgroup limit). Best-effort: works on Linux and Windows;
  macOS has no real per-core pinning, so it is ignored there. Omit it to leave the thread unpinned
  (the default — auto-pinning is opt-in because on a small or shared host it can hurt).

## Send backends

The addon opens the fastest backend available on the platform and **falls back to pcap** if a native
backend cannot be opened. The `backend` field on the `progress`/`done` events reports the one actually
in use.

| Platform | Priority (highest first) | `backend` value |
| --- | --- | --- |
| Linux | TX_RING (PACKET_MMAP) → PF_PACKET (raw `AF_PACKET`) → pcap | `tx_ring` / `pf_packet` / `pcap` |
| BSD / macOS | BPF (`/dev/bpf`) → pcap | `bpf` / `pcap` |
| Windows | pcap (Npcap, `wpcap.dll` loaded at runtime) | `pcap` |

## API

```ts
class Replay extends EventEmitter {
  constructor(options: IReplayOptions)
  addFrames(frames: IReplayFrame[]): void   // queue frames; may be called multiple times before start()
  start(): void                             // begin transmitting on the send thread (idempotent while running)
  stop(): void                              // ask the thread to stop after the current frame; a 'done' still fires
  get running(): boolean                    // true while transmitting

  on('progress', (p: IReplayProgress) => void): this
  on('done',     (p: IReplayProgress) => void): this   // exactly one terminal done…
  on('error',    (e: Error) => void): this             // …or one error
}
```

`addFrames` copies frames into native memory immediately, so the source buffers can be reused right
after. After `start()`, `progress` fires periodically and then exactly one terminal `done` (with the
final totals) or `error`.

### Progress (`progress` / `done` payload)

```ts
interface IReplayProgress {
  sent: number       // frames successfully put on the wire so far
  bytes: number      // bytes successfully sent so far
  failed: number     // frames the backend refused (send error)
  elapsedMs: number  // wall-clock elapsed since the run started
  loop: number       // current pass index (0-based)
  pps: number        // achieved rate, packets per second (over the whole run so far)
  mbps: number       // achieved throughput, megabits per second (over the whole run so far)
  backend: string    // the send backend actually in use (see table above)
}
```

## No prebuilt binaries

By project policy this package never ships compiled `.node` files — the native addon is always built
locally from source at install time. Make sure the toolchain and pcap headers listed under
[Install](#install) are present, and remember that transmitting frames normally requires elevated
privileges.
