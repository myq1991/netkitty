# Browser verification / 浏览器双端验证

`@netkitty/analysis` runs identically in node and in a real browser: the same `Analysis` facade over a
single worker, only the read backend (node `FileHandle` vs browser `Blob`) and the worker channel
(`worker_threads` vs `Web Worker`) differ. This note records how the browser path is verified against
node in a real Chromium, so a regression can be reproduced.

`@netkitty/analysis` 在 node 与真实浏览器中行为一致：同一个 `Analysis` 门面 + 单 worker，只有读后端
（node `FileHandle` / 浏览器 `Blob`）与 worker 通道（`worker_threads` / `Web Worker`）不同。本文记录如何
在真实 Chromium 里对照 node 验证浏览器路径。

## What is checked / 验证内容

Same `iec104.pcap` fixture, opened both ways, asserting field-for-field equality:

- `frameCount`, `getFrames(0, n)` rows (index / timestamp / length / topProtocol / conversationKey)
- `getFrame(0).layers` decode (`[eth, ipv4, tcp]`)
- `filter('tcp')` match count
- `attachReducer(new ConversationsReducer())` result

## Reproduce / 复现

Requires the browser bundle to be built with esbuild and a Buffer polyfill (codec/pcap-core use the
`Buffer` global). esbuild and the `buffer` polyfill are dev-only tools, not runtime deps.

```bash
# from repo root
npm run build --workspace @netkitty/analysis     # produce dist/
npm i buffer --no-save                            # Buffer polyfill for the bundle only

# main-thread bundle: exposes { Analysis, WebWorkerChannel, ConversationsReducer } on globalThis.NK.
#   entry sets globalThis.Buffer = require('buffer').Buffer, then requires:
#     dist/lib/streaming/Analysis, .../worker/WebWorkerChannel, .../reducers/ConversationsReducer
#   the node-only lazy factory is excluded so the browser bundle carries no node builtins:
npx esbuild main-entry.js  --bundle --format=iife --platform=browser \
    --external:*/spawnNodeAnalysisChannel --outfile=main.bundle.js

# worker bundle: requires dist/lib/streaming/worker/analysisWorkerBrowser (Buffer set first)
npx esbuild worker-entry.js --bundle --format=iife --platform=browser --outfile=worker.bundle.js
```

Build an HTML page that inlines `main.bundle.js`, carries `worker.bundle.js` as text (loaded via
`new Worker(URL.createObjectURL(new Blob([...])))`), and embeds the pcap fixture as base64. Serve it
over http (file:// is blocked) and run in a real Chromium:

```js
const {Analysis, WebWorkerChannel, ConversationsReducer} = globalThis.NK
const worker = new Worker(URL.createObjectURL(new Blob([workerBundleText], {type: 'text/javascript'})))
const analysis = new Analysis({}, () => new WebWorkerChannel(worker))
await analysis.open(new Blob([fixtureBytes]))
// frameCount / getFrames / getFrame / filter / attachReducer(ConversationsReducer) ...
await analysis.close()
```

## Result (iec104.pcap) / 验证结果

Browser output equals node output field-for-field:

| metric | value (node == Chromium) |
|---|---|
| frameCount | 105 |
| first row | index 0, ts 1372918996.78845, len 66, tcp, `tcp\|10.20.100.108:2404\|10.20.102.1:46413` |
| getFrame(0).layers | `[eth, ipv4, tcp]` |
| filter('tcp') | 105 matches |
| Conversations | 1 conversation, 105 packets, 8431 bytes |
