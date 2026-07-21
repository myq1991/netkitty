import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../helper/BufferToHex'
import {HexToBuffer} from '../helper/HexToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/**
 * Wake-on-LAN "magic packet" (AMD Magic Packet Technology), carried directly in an Ethernet II frame
 * with EtherType 0x0842 (an Ethernet child — no IP/UDP). The magic packet has a fixed shape: a 6-byte
 * synchronization stream of all ones (0xFF ×6), followed by the target adapter's 6-byte MAC address
 * repeated exactly 16 times (96 bytes), optionally followed by a 0/4/6-byte SecureOn password. There is
 * no length field — the payload runs to the end of the frame.
 *
 * The 16 MAC repetitions are, by definition, identical, so the target MAC is surfaced once (decoded from
 * the first repetition) and re-emitted 16× on encode — a well-formed magic packet round-trips
 * byte-for-byte. The 6-byte sync stream is kept verbatim as hex (so an odd/crafted stream still
 * reproduces) and any trailing SecureOn password bytes are kept verbatim as hex (0/4/6 bytes; taken to
 * the end of the frame). Nothing is recomputed on encode. WoL is a leaf header — nothing rides above it.
 *
 * Note: WoL magic packets are also frequently sent as the payload of a UDP datagram (well-known ports 9
 * and 7, or 0). This codec handles only the EtherType 0x0842 direct-on-Ethernet framing; the UDP-carried
 * form is a separate demux (udpport) and is not attempted here.
 */
export class WakeOnLAN extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (WakeOnLAN.#schemaCache ??= WakeOnLAN.#buildSchema())
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'WoL target=${targetMac}',
            properties: {
                //The 6-byte synchronization stream. In a well-formed magic packet it is all ones
                //(0xFF ×6); kept verbatim as hex so a crafted stream still round-trips byte-for-byte.
                syncStream: this.fieldHex('syncStream', 0, 6, 'Sync Stream'),
                //The target adapter's MAC address, decoded from the first of the 16 identical repetitions
                //(offset 6). On encode it is written back 16 times over offsets 6..101 (96 bytes) — the
                //defining property of a magic packet, so a well-formed packet reproduces exactly.
                targetMac: {
                    type: 'string',
                    label: 'Target MAC',
                    minLength: 17,
                    maxLength: 17,
                    contentEncoding: StringContentEncodingEnum.MAC,
                    decode: function (this: WakeOnLAN): void {
                        //Read (consume) the whole 96-byte MAC block so the header length covers all 16
                        //repetitions; the value is taken from the first repetition (they are identical).
                        const block: Buffer = this.readBytes(6, 96)
                        this.instance.targetMac.setValue(
                            Array.from(block.subarray(0, 6))
                                .map((value: number): string => value.toString(16).padStart(2, '0'))
                                .join(':')
                        )
                    },
                    encode: function (this: WakeOnLAN): void {
                        const mac: number[] = this.instance.targetMac
                            .getValue('00:00:00:00:00:00', (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                            .toString()
                            .split(':')
                            .map((value: string): number => parseInt(value, 16))
                            .map((value: number): number => value ? value : 0)
                        const macBuffer: Buffer = Buffer.alloc(6, Buffer.from(mac))
                        //Re-emit the 6-byte MAC 16 times (offsets 6..101) — the magic-packet MAC block.
                        for (let i: number = 0; i < 16; i++) this.writeBytes(6 + i * 6, macBuffer)
                    }
                },
                //Optional SecureOn password after the 96-byte MAC block (0/4/6 bytes, RFC-less vendor
                //extension). Kept verbatim as hex, taken to the end of the frame; empty when absent.
                //WoL is a leaf so it consumes to the end — nothing is left for the codec's recursion.
                password: {
                    type: 'string',
                    label: 'SecureOn Password',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: WakeOnLAN): void {
                        const available: number = this.packet.length - this.startPos
                        this.instance.password.setValue(available > 102 ? BufferToHex(this.readBytes(102, available - 102)) : '')
                    },
                    encode: function (this: WakeOnLAN): void {
                        const password: string = this.instance.password.getValue('')
                        if (password) this.writeBytes(102, HexToBuffer(password))
                    }
                }
            }
        }
    }

    public readonly id: string = 'wol'

    public readonly name: string = 'Wake-on-LAN'

    public readonly nickname: string = 'WoL'

    public readonly matchKeys: string[] = ['ethertype:0842']

    public match(): boolean {
        //An Ethernet child selected by EtherType 0x0842 (stored as a lowercase 4-hex string). Require the
        //full sync stream + MAC block (6 + 96 = 102 bytes) and the all-ones 6-byte sync-stream signature,
        //so non-magic 0x0842 traffic falls through to raw.
        if (!this.prevCodecModule || this.prevCodecModule.id !== 'eth') return false
        if (this.prevCodecModule.instance.etherType.getValue() !== '0842') return false
        if (this.packet.length - this.startPos < 102) return false
        const sync: Buffer = this.readBytes(0, 6, true)
        for (let i: number = 0; i < 6; i++) {
            if (sync[i] !== 0xff) return false
        }
        //A valid magic packet repeats the target MAC identically 16 times. Since this codec re-emits the
        //block by reconstructing it from a single MAC, a frame whose 16 repetitions are NOT all identical
        //could not round-trip byte-for-byte — so it is not a magic packet: leave it to RawData rather than
        //claim it and silently rewrite the block.
        const block: Buffer = this.readBytes(6, 96, true)
        for (let rep: number = 1; rep < 16; rep++) {
            for (let b: number = 0; b < 6; b++) {
                if (block[rep * 6 + b] !== block[b]) return false
            }
        }
        return true
    }

    //A leaf header — nothing demuxes above Wake-on-LAN.
    public readonly demuxProducers: DemuxProducer[] = []

}
