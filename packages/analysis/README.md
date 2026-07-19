# @netkitty/analysis

Streaming, cross-packet analysis for capture files — a programmable, Wireshark-style front door over
pcap/pcapng. The same `Analysis` facade runs in **node and the browser**: heavy work (read → parse →
partial-decode → columnar index → decode) lives in a single worker, so `open()` never blocks the
caller and `close()` releases everything by terminating the worker.

> 中文文档见 [README.zh-CN.md](./README.zh-CN.md)。

Built on [`@netkitty/codec`](../codec) (protocol decoding) and [`@netkitty/pcap-core`](../pcap-core)
(pcap/pcapng parsing) — both pure-buffer and browser-safe.

## Install

```bash
npm i @netkitty/analysis
# or use the aggregate package: import ... from 'netkitty/analysis'
```

## Quick start (node)

```ts
import {Analysis, ConversationsReducer} from '@netkitty/analysis'

const analysis = new Analysis()
await analysis.open('/path/to/capture.pcap')      // bounded file: index, then emit 'complete'

analysis.frameCount()                              // total frames indexed
const rows = await analysis.getFrames(0, 100)      // lightweight rows (no decoded layers)
const frame = await analysis.getFrame(42)          // one frame WITH decoded layers
const tcp = await analysis.filter('tcp')           // matching frame indices

const conversations = new ConversationsReducer()
await analysis.attachReducer(conversations)        // replays every indexed frame, then follows live
conversations.result()                             // rolling snapshot (no finalize)

await analysis.close()                             // terminate the worker, release everything
```

## Reducers

A reducer is a pluggable rolling analysis fed every frame; `result()` is a snapshot at any time (there
is no finalize). `attachReducer` **replays** the whole indexed backlog first, then follows the live
stream — so stats are complete the moment it resolves.

- **Built-in** (exported, attach them yourself): `ConversationsReducer`, `EndpointsReducer`,
  `TcpStreamReducer` (retransmissions / duplicate ACKs / RTT).
- **Factories**: `reduceReducer(seed, fold)`, `groupByReducer(keyOf, seed, fold)`.
- **Custom**: implement `IAnalysisReducer<T>` (`update(frame, ctx)` / `result()` / `reset()`); declare
  `needs: string[]` to receive only those protocol layers (the worker projects them, cutting cross-thread bytes).

```ts
import {reduceReducer, groupByReducer} from '@netkitty/analysis'

const totalBytes = reduceReducer(0, (sum, frame) => sum + frame.length)
const perProtocol = groupByReducer(f => f.topProtocol, 0, count => count + 1)
```

## Live capture (watch)

`watch()` tails a growing capture, feeding reducers with phase `'live'`. The index is **unbounded by
default** (you own the memory). `maxFrames` is an optional guard: past the cap the oldest indexed
frames are FIFO-evicted (Wireshark-style ring buffer), keeping a long-running tail bounded — only the
in-memory index is dropped, the file on disk is untouched.

```ts
const analysis = new Analysis()                         // default: unbounded index
analysis.on('frame', row => { /* new indexed frame */ })
await analysis.watch('/path/to/growing.pcap')           // tails the file; reducers get phase 'live'

// optional memory guard for a long-running tail:
// new Analysis({maxFrames: 1_000_000})  // FIFO-evict the oldest past the cap → bounded memory
```

## Browser

The facade is environment-agnostic — inject a browser worker channel; the worker is a bundled
`analysisWorkerBrowser` entry (esbuild + Buffer polyfill), and the source is a `File`/`Blob`:

```ts
import {Analysis, WebWorkerChannel} from '@netkitty/analysis'

const worker = new Worker(/* bundled analysisWorkerBrowser.js */)
const analysis = new Analysis({}, () => new WebWorkerChannel(worker))
await analysis.open(file)   // file: a File/Blob
```

node and browser produce field-for-field identical results.

## Legacy (retained)

The batch `FlowAnalyzer` and `TcpStreamAnalyzer` (which take an in-memory `AnalysisPacket[]`) remain
exported and unchanged.
