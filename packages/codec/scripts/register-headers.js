#!/usr/bin/env node
/*
 * Auto-registers any header class under src/lib/codec/headers/ that is not yet exported from
 * PacketHeaders.ts. Each header file has exactly one `export class X`, and the codec's HEADER_CODECS is
 * built from `Object.values(packetHeaders)`, so registration is just a re-export line. New leaf protocols
 * are inserted before the VLAN_802dot1Q export (the tail block of tag/TLS/IEC104 headers), preserving the
 * existing ordering convention. Idempotent: run it after dropping new header files in to wire them up.
 *
 * Usage:  node scripts/register-headers.js
 * Part of the batch-integration flow:  register-headers → build:test → UPDATE_GOLDEN=1 (goldens +
 * _layergraph snapshot) → full test run. Differential.spec mappings are intentionally NOT auto-generated
 * (tshark↔field-name matching needs judgment); a new protocol is simply unmapped there until a mapping is
 * added, so it is covered by byte round-trip + golden meanwhile.
 */
'use strict'
const fs = require('node:fs')
const path = require('node:path')

const root = path.resolve(__dirname, '..')
const headersDir = path.join(root, 'src', 'lib', 'codec', 'headers')
const packetHeadersPath = path.join(root, 'src', 'lib', 'codec', 'PacketHeaders.ts')

// RawData/BaseHeader are infrastructure. WebSocket is intentionally NOT auto-registered: it has no port
// or content signature a single-packet stateless codec can safely match on (it is negotiated by an HTTP
// Upgrade handshake, which is cross-packet state), so it would over-claim TCP payloads in the default
// codec. It is a decode-as-only frame codec, reachable via `new Codec([WebSocket])`.
const NON_REGISTERABLE = new Set(['RawData', 'BaseHeader', 'WebSocket'])

let packetHeaders = fs.readFileSync(packetHeadersPath, 'utf8')
const registered = new Set([...packetHeaders.matchAll(/export\s*\{\s*(\w+)\s*\}/g)].map((m) => m[1]))

const toAdd = []
for (const file of fs.readdirSync(headersDir).sort()) {
    if (!file.endsWith('.ts')) continue
    const src = fs.readFileSync(path.join(headersDir, file), 'utf8')
    const m = src.match(/export\s+class\s+(\w+)\b/)
    if (!m) continue
    const cls = m[1]
    const base = file.replace(/\.ts$/, '')
    if (NON_REGISTERABLE.has(cls) || registered.has(cls)) continue
    toAdd.push({cls, base})
}

if (toAdd.length === 0) {
    console.log('register-headers: nothing new to register.')
    process.exit(0)
}

const anchor = "export {VLAN_802dot1Q} from './headers/VLAN_802dot1Q'"
if (!packetHeaders.includes(anchor)) {
    console.error('register-headers: could not find the VLAN_802dot1Q anchor in PacketHeaders.ts')
    process.exit(1)
}
const block = toAdd.map((x) => `export {${x.cls}} from './headers/${x.base}'`).join('\n')
packetHeaders = packetHeaders.replace(anchor, `${block}\n${anchor}`)
fs.writeFileSync(packetHeadersPath, packetHeaders)
console.log(`register-headers: registered ${toAdd.length} — ${toAdd.map((x) => x.cls).join(', ')}`)
