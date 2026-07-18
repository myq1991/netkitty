import {test} from 'node:test'
import assert from 'node:assert'
import {Codec} from '../../src/lib/codec/Codec'
import {LoadPacket} from '../lib/Fixtures'
import {CodecDecodeResult} from '../../src/lib/codec/types/CodecDecodeResult'

const codec: Codec = new Codec()

async function summaryOf(name: string): Promise<string> {
    const decoded: CodecDecodeResult[] = await codec.decode(LoadPacket(name).buffer)
    return codec.summary(decoded)
}

// 3b: the one-line Info summary — the innermost layer with a declared template wins.
test('summary: renders the innermost layer template (TCP)', async (): Promise<void> => {
    assert.strictEqual(await summaryOf('tcp/uto-option'), '12345 → 80 Seq=1 Ack=1 Win=65535')
})

test('summary: falls back to an outer layer template when the inner layer has none (UDP → IPv4)', async (): Promise<void> => {
    // UDP declares no template, so the IPv4 template one layer out is used.
    assert.strictEqual(await summaryOf('udp/netbios'), '192.168.1.198 → 192.168.1.255')
})

test('summary: falls back to the innermost non-raw layer name when no template exists (ARP)', async (): Promise<void> => {
    assert.strictEqual(await summaryOf('arp/baseline'), 'Address Resolution Protocol')
})
