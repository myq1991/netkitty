import {execFileSync} from 'node:child_process'
import {writeFileSync, mkdtempSync, rmSync} from 'node:fs'
import {tmpdir} from 'node:os'
import path from 'node:path'

/**
 * Wireshark/tshark bridge used as a differential oracle: it dissects a raw Ethernet frame and
 * returns tshark's own field tree, so netkitty's decode can be checked against an independent
 * ground truth. This catches "symmetric-wrong" decodes (decode and encode share a wrong
 * interpretation) that a byte round-trip cannot see.
 */

export type TsharkLayers = {[layer: string]: {[field: string]: unknown}}

let cachedAvailable: boolean | undefined = undefined

/**
 * True if a usable tshark is on PATH. Cached; the differential tests skip themselves when false so
 * the suite still runs in environments without Wireshark installed.
 */
export function tsharkAvailable(): boolean {
    if (cachedAvailable !== undefined) return cachedAvailable
    try {
        execFileSync('tshark', ['--version'], {stdio: 'ignore'})
        cachedAvailable = true
    } catch (e) {
        cachedAvailable = false
    }
    return cachedAvailable
}

/**
 * Dissect a single Ethernet frame with tshark and return the first packet's layer/field tree.
 * The frame is wrapped in a minimal classic-pcap file (link type 1 = Ethernet).
 */
export function tsharkLayers(packet: Buffer): TsharkLayers {
    const globalHeader: Buffer = Buffer.alloc(24)
    globalHeader.writeUInt32LE(0xA1B2C3D4, 0) // magic (LE, µs)
    globalHeader.writeUInt16LE(2, 4)          // version major
    globalHeader.writeUInt16LE(4, 6)          // version minor
    globalHeader.writeUInt32LE(65535, 16)     // snaplen
    globalHeader.writeUInt32LE(1, 20)         // network = Ethernet
    const recordHeader: Buffer = Buffer.alloc(16)
    recordHeader.writeUInt32LE(packet.length, 8)  // incl_len
    recordHeader.writeUInt32LE(packet.length, 12) // orig_len
    const pcap: Buffer = Buffer.concat([globalHeader, recordHeader, packet])

    const dir: string = mkdtempSync(path.join(tmpdir(), 'nk-tshark-'))
    const file: string = path.join(dir, 'p.pcap')
    try {
        writeFileSync(file, pcap)
        const out: string = execFileSync('tshark', ['-r', file, '-T', 'json'], {maxBuffer: 32 * 1024 * 1024}).toString()
        const parsed: any[] = JSON.parse(out)
        const layers: TsharkLayers | undefined = parsed[0] && parsed[0]._source && parsed[0]._source.layers
        return layers ? layers : {}
    } finally {
        rmSync(dir, {recursive: true, force: true})
    }
}
