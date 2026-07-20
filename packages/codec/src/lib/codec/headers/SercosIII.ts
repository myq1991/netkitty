import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../../helper/BufferToHex'
import {HexToBuffer} from '../../helper/HexToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/**
 * Sercos III — the real-time industrial Ethernet of the Sercos automation bus (IEC 61491 / IEC 61158,
 * IEC 61784 CPF-16), carried directly in an Ethernet II frame with EtherType 0x88CD (an Ethernet child —
 * no IP/UDP). Every communication cycle the master emits Master Data Telegrams (MDT) and the slaves answer
 * with Acknowledge Telegrams (AT); both frame kinds share the same EtherType and are distinguished by the
 * Telegram Type bit in the first header byte.
 *
 * The frame opens with the Sercos III telegram header. This minimal slice structures the fixed leading
 * bytes and keeps the per-device payload verbatim:
 *
 *   Byte 0 — Telegram Type field (a bitfield, MSB-first per the Wireshark `siii` dissector):
 *     - bit 7 (0x80) channel          — 0 = P-Telegram (primary line), 1 = S-Telegram (secondary line)
 *     - bit 6 (0x40) telegramType      — 0 = MDT (Master Data Telegram), 1 = AT (Acknowledge Telegram)
 *     - bit 5 (0x20) cycleCountValid   — the MST cycle count is valid
 *     - bit 4 (0x10) reserved          — preserved verbatim for a byte-perfect round-trip
 *     - bits 0..3 (0x0f) telegramNumber— MDT/AT index within the cycle (0..15)
 *   Byte 1 — Phase field (the Master Sync Telegram, MST):
 *     - the Phase occupies mask 0x8f (bit 7 = phase switching, bits 0..3 = communication phase CP0..CP4),
 *       a non-contiguous field kept as one value; the Cycle Count occupies mask 0x70 (bits 4..6).
 *   Bytes 2..5 — CRC32 of the MST, kept verbatim (little-endian on the wire per the dissector) and never
 *     recomputed, so a captured frame round-trips byte-for-byte.
 *
 * Everything after the 6-byte header (the phase-dependent per-device connection / service-channel data) is
 * command- and topology-dependent, so this slice keeps it verbatim as `data` hex (byte-perfect), bounded by
 * the end of the Ethernet payload (Sercos III has no length field of its own — it runs to the end of the
 * frame, like LLDP/GOOSE). Structuring the per-device bodies (device control/status, service channel, hot
 * plug) is a deferred slice. The MST header is genuine for the CP0–CP2 scanning phases and MDT0; for a
 * CP3/CP4 operational device telegram the byte-1..5 labels are nominal but the bytes are still reproduced
 * exactly because every header field is read and re-emitted verbatim.
 */
export class SercosIII extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (SercosIII.#schemaCache ??= SercosIII.#buildSchema())
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'Sercos III type=${telegramType} tel=${telegramNumber} phase=${phase}',
            properties: {
                //==== Byte 0: Telegram Type field ====
                //Each sub-field owns its own bits of byte 0 via writeBits (which masks each field, so they
                //never clobber). All 8 bits are accounted for (0x80 channel, 0x40 type, 0x20 cycleCountValid,
                //0x10 reserved, 0x0f telegramNumber) so byte 0 round-trips exactly.
                channel: {
                    type: 'integer',
                    label: 'Channel',
                    minimum: 0,
                    maximum: 1,
                    decode: function (this: SercosIII): void {
                        this.instance.channel.setValue(this.readBits(0, 1, 0, 1))
                    },
                    encode: function (this: SercosIII): void {
                        this.writeBits(0, 1, 0, 1, this.instance.channel.getValue(0) & 0x1)
                    }
                },
                telegramType: {
                    type: 'integer',
                    label: 'Telegram Type',
                    minimum: 0,
                    maximum: 1,
                    decode: function (this: SercosIII): void {
                        this.instance.telegramType.setValue(this.readBits(0, 1, 1, 1))
                    },
                    encode: function (this: SercosIII): void {
                        this.writeBits(0, 1, 1, 1, this.instance.telegramType.getValue(0) & 0x1)
                    }
                },
                cycleCountValid: {
                    type: 'integer',
                    label: 'Cycle Count Valid',
                    minimum: 0,
                    maximum: 1,
                    decode: function (this: SercosIII): void {
                        this.instance.cycleCountValid.setValue(this.readBits(0, 1, 2, 1))
                    },
                    encode: function (this: SercosIII): void {
                        this.writeBits(0, 1, 2, 1, this.instance.cycleCountValid.getValue(0) & 0x1)
                    }
                },
                //Bit 4 (0x10) of byte 0 is unassigned in the dissector — kept verbatim so no bit is lost.
                reserved: {
                    type: 'integer',
                    label: 'Reserved',
                    minimum: 0,
                    maximum: 1,
                    default: 0,
                    decode: function (this: SercosIII): void {
                        this.instance.reserved.setValue(this.readBits(0, 1, 3, 1))
                    },
                    encode: function (this: SercosIII): void {
                        this.writeBits(0, 1, 3, 1, this.instance.reserved.getValue(0) & 0x1)
                    }
                },
                telegramNumber: {
                    type: 'integer',
                    label: 'Telegram Number',
                    minimum: 0,
                    maximum: 15,
                    decode: function (this: SercosIII): void {
                        this.instance.telegramNumber.setValue(this.readBits(0, 1, 4, 4))
                    },
                    encode: function (this: SercosIII): void {
                        this.writeBits(0, 1, 4, 4, this.instance.telegramNumber.getValue(0) & 0x0f)
                    }
                },
                //==== Byte 1: Phase field (MST) ====
                //Phase is a non-contiguous field (mask 0x8f = bit 7 + bits 0..3); Cycle Count is mask 0x70
                //(bits 4..6). `phase` owns the single write of byte 1, reassembling both values so they never
                //clobber — phase's 0x8f and cycleCnt's 0x70 are disjoint and together cover all 8 bits.
                phase: {
                    type: 'integer',
                    label: 'Phase',
                    minimum: 0,
                    maximum: 143,
                    decode: function (this: SercosIII): void {
                        this.instance.phase.setValue(this.readBytes(1, 1)[0] & 0x8f)
                    },
                    encode: function (this: SercosIII): void {
                        const node: any = this.instance.phase
                        let phase: number = node.getValue(0, (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                        if (phase > 0x8f) {
                            this.recordError(node.getPath(), 'Maximum value is 143')
                            phase = 0x8f
                        }
                        if (phase < 0) {
                            this.recordError(node.getPath(), 'Minimum value is 0')
                            phase = 0
                        }
                        node.setValue(phase)
                        const cycleCnt: number = this.instance.cycleCnt.getValue(0) & 0x07
                        this.writeBytes(1, Buffer.from([(phase & 0x8f) | (cycleCnt << 4)]))
                    }
                },
                //Decode-only: bits 4..6 of byte 1. Written by `phase`'s encode (see above).
                cycleCnt: {
                    type: 'integer',
                    label: 'Cycle Count',
                    minimum: 0,
                    maximum: 7,
                    default: 0,
                    decode: function (this: SercosIII): void {
                        this.instance.cycleCnt.setValue((this.readBytes(1, 1)[0] >> 4) & 0x07)
                    }
                },
                //==== Bytes 2..5: MST CRC32 ====
                //Honored verbatim (little-endian on the wire) and never recomputed, so a captured frame
                //round-trips byte-for-byte.
                crc32: this.fieldHex('crc32', 2, 4, 'CRC32'),
                //==== Bytes 6..end: per-device payload ====
                //Kept verbatim (byte-perfect). Sercos III has no length field of its own — it runs to the end
                //of the Ethernet payload (like LLDP/GOOSE), so the body is bounded by the captured frame.
                data: {
                    type: 'string',
                    label: 'Data',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: SercosIII): void {
                        const remaining: number = this.packet.length - this.startPos
                        this.instance.data.setValue(remaining > 6 ? BufferToHex(this.readBytes(6, remaining - 6)) : '')
                    },
                    encode: function (this: SercosIII): void {
                        const data: string = this.instance.data.getValue('')
                        if (data) this.writeBytes(6, HexToBuffer(data))
                    }
                }
            }
        }
    }

    public readonly id: string = 'sercos3'

    public readonly name: string = 'Sercos III'

    public readonly nickname: string = 'SercosIII'

    public readonly matchKeys: string[] = ['ethertype:88cd']

    public match(): boolean {
        //An Ethernet child selected by EtherType 0x88CD (stored as a lowercase 4-hex string). 0x88CD is
        //assigned exclusively to Sercos III, so the EtherType alone is a reliable discriminator. Require the
        //full 6-byte MST header (Telegram Type + Phase field + CRC32) to be present so a tiny truncated
        //fragment falls through to raw instead of being claimed.
        if (!this.prevCodecModule || this.prevCodecModule.id !== 'eth') return false
        if (this.prevCodecModule.instance.etherType.getValue() !== '88cd') return false
        return this.packet.length - this.startPos >= 6
    }

    //A leaf header — the per-device connection / service-channel bodies require phase- and topology-dependent
    //parsing (deferred slice).
    public readonly demuxProducers: DemuxProducer[] = []

}
