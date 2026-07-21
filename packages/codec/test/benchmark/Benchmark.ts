import {AllPacketFixtureNames, LoadPacket} from '../lib/Fixtures'
import {Codec} from '../../src/Codec'
import {CodecDecodeResult} from '../../src/types/CodecDecodeResult'

/**
 * Throughput benchmark for the codec decode/encode hot path. Not a test (no .spec suffix, so the
 * node:test runner never picks it up). Run with: node dist/tests/benchmark/Benchmark.js
 *
 * It reports microseconds-per-packet and packets-per-second for decode and encode across the
 * whole fixture corpus, so performance changes are measured, not guessed.
 */
async function main(): Promise<void> {
    const codec: Codec = new Codec()
    const names: string[] = AllPacketFixtureNames()
    const buffers: Buffer[] = names.map((name: string): Buffer => LoadPacket(name).buffer)
    // Pre-decode once so the encode benchmark has real inputs.
    const decoded: CodecDecodeResult[][] = []
    for (const buffer of buffers) decoded.push(await codec.decode(buffer))

    const rounds: number = 400 // full passes over the corpus
    const packets: number = rounds * buffers.length

    // Warm up JIT.
    for (let r: number = 0; r < 20; r++) {
        for (const buffer of buffers) await codec.decode(buffer)
        for (const input of decoded) await codec.encode(input)
    }

    const decodeStart: bigint = process.hrtime.bigint()
    for (let r: number = 0; r < rounds; r++) {
        for (const buffer of buffers) await codec.decode(buffer)
    }
    const decodeNs: number = Number(process.hrtime.bigint() - decodeStart)

    const encodeStart: bigint = process.hrtime.bigint()
    for (let r: number = 0; r < rounds; r++) {
        for (const input of decoded) await codec.encode(input)
    }
    const encodeNs: number = Number(process.hrtime.bigint() - encodeStart)

    const fmt: (ns: number) => string = (ns: number): string => {
        const usPerPacket: number = ns / packets / 1000
        const perSec: number = packets / (ns / 1e9)
        return `${usPerPacket.toFixed(2)} µs/packet   ${Math.round(perSec).toLocaleString()} packets/s`
    }
    console.log(`fixtures: ${buffers.length}   rounds: ${rounds}   packets: ${packets.toLocaleString()}`)
    console.log(`decode:  ${fmt(decodeNs)}`)
    console.log(`encode:  ${fmt(encodeNs)}`)
}

main().catch((e: Error): void => {
    console.error(e)
    process.exit(1)
})
