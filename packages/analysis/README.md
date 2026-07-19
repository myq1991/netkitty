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

- **Built-in** (exported): `ConversationsReducer`, `EndpointsReducer`, `TcpStreamReducer`
  (retransmissions / duplicate ACKs / RTT). For Conversations/Endpoints prefer the shortcut methods
  `analysis.conversations()` / `analysis.endpoints()` — they compute the same result **entirely inside
  the worker** by scanning the index columns (no re-decode, no per-frame cross-thread transfer, zero
  main-thread work), so they stay fast even at hundreds of millions of frames.
- **Factories**: `reduceReducer(seed, fold)`, `groupByReducer(keyOf, seed, fold)`.
- **Custom**: implement `IAnalysisReducer<T>` — see [Writing a custom reducer](#writing-a-custom-reducer).

```ts
import {reduceReducer, groupByReducer} from '@netkitty/analysis'

const totalBytes = reduceReducer(0, (sum, frame) => sum + frame.length)
const perProtocol = groupByReducer(f => f.topProtocol, 0, count => count + 1)
```

### Writing a custom reducer

A reducer is a plain object (or class) implementing `IAnalysisReducer<T>`:

```ts
interface IAnalysisReducer<T> {
  update(frame: Frame, context: UpdateContext): void  // called once per frame (replay, then live)
  result(): T                                          // rolling snapshot — callable any time, no finalize
  reset(): void                                        // clear all accumulated state
  readonly needs?: string[]                            // optional: layer ids you read (projection)
  readonly indexOnly?: boolean                         // optional: correctness/perf contract, see below
}
```

- **`update(frame, context)`** runs for every frame. `frame` carries `index`, `timestamp`, `length`,
  `topProtocol`, `conversationKey`, and `layers` (the decoded protocol tree). `context` carries `index`,
  `total`, and `phase` — `'replay'` while catching up on the already-indexed backlog, `'live'` while
  tailing under `watch()`.
- **`result()`** is a rolling snapshot; there is **no finalize**, so call it whenever (mid-replay,
  mid-tail). **`reset()`** clears state.
- Keep state bounded **per conversation/endpoint**, not per frame — the built-ins hold a first/last
  index span instead of a member-frame list, so memory stays flat across hundreds of millions of frames.
- **`needs`** (optional): the layer ids you actually read, e.g. `['ipv4', 'tcp']`. The worker then
  transfers only those layers across the thread boundary instead of the whole tree — pure bandwidth win,
  no behavioural change.
- **`indexOnly`** (optional — a **correctness contract**, not just a hint): set `true` **only if**
  `update` reads nothing beyond frame metadata (`index` / `timestamp` / `length` / `topProtocol` /
  `conversationKey`) and the five-tuple carried in `layers` — the endpoint addresses and ports
  (`eth` `smac`/`dmac`, `ipv4`/`ipv6` `sip`/`dip`, `tcp`/`udp` `srcport`/`dstport`). Replay then feeds
  frames **synthesized straight from the index columns, skipping the per-frame re-decode** — measured
  ~13× faster on large captures. ⚠️ If you set it while reading any deeper field (`ipv4.ttl`,
  `tcp.flags`, TLS SNI, payload …), that field is simply **absent** on replay and your result is
  silently wrong. When unsure, leave it unset — full decode is the safe default. `ConversationsReducer`
  and `EndpointsReducer` set it (five-tuple only); `TcpStreamReducer` does not (it reads seq/ack/flags).

```ts
import {IAnalysisReducer, Frame, UpdateContext} from '@netkitty/analysis'

//Counts frames per top-level protocol. Reads only metadata → indexOnly is safe.
class ProtocolCounter implements IAnalysisReducer<Record<string, number>> {
  readonly indexOnly = true
  #counts: Record<string, number> = {}
  update(frame: Frame, _context: UpdateContext): void {
    this.#counts[frame.topProtocol] = (this.#counts[frame.topProtocol] ?? 0) + 1
  }
  result(): Record<string, number> { return {...this.#counts} }
  reset(): void { this.#counts = {} }
}
```

A reducer runs **on the main thread** — its `update` closure can't be structured-cloned into the worker.
That is fine: `update` is cheap arithmetic; the expensive part (read + decode) already happened in the
worker, and `indexOnly`/`needs` govern how much of it crosses back. A reducer may also extend an event
emitter and push its own `progress`/`update` events from inside `update()`.

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
