import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {ProtocolFieldJSONSchema} from '../../schema/ProtocolFieldJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../../helper/BufferToHex'
import {HexToBuffer} from '../../helper/HexToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/**
 * BFD — Bidirectional Forwarding Detection Control (RFC 5880), UDP port 3784 (single-hop) and 4784
 * (multi-hop). The mandatory section is 24 bytes: a first byte carrying Version[3] (= 1) and a 5-bit
 * Diagnostic code, a second byte carrying the 2-bit Session State (0 AdminDown / 1 Down / 2 Init /
 * 3 Up) followed by six flag bits (P Poll, F Final, C Control-Plane-Independent, A Authentication
 * Present, D Demand, M Multipoint), a Detect Mult (detection-time multiplier), a Length (of the whole
 * BFD Control packet in bytes), then five 4-byte fields: My Discriminator, Your Discriminator, and the
 * Desired Min TX / Required Min RX / Required Min Echo RX intervals (all in microseconds).
 *
 * If the A (Authentication Present) flag is set an optional Authentication Section follows the
 * mandatory 24 bytes (Auth Type, Auth Len, then type-specific auth data). It is kept verbatim as
 * `authSection` hex so any auth variant round-trips byte-for-byte; when A is clear it is empty. The
 * Length field is honoured verbatim (not recomputed) so a captured packet re-encodes byte-for-byte.
 * BFD Control is a leaf — nothing rides on top of it.
 */
export class BFD extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (BFD.#schemaCache ??= BFD.#buildSchema())
    }

    /** The payload length bounded by the UDP datagram (so retained padding/FCS is not absorbed). */
    #payloadLength(): number {
        let available: number = this.packet.length - this.startPos
        if (this.prevCodecModule && this.prevCodecModule.id === 'udp') {
            const udpLength: number = this.prevCodecModule.instance.length.getValue(0)
            if (udpLength >= 8 && udpLength - 8 < available) available = udpLength - 8
        }
        return available < 0 ? 0 : available
    }

    /**
     * A single flag bit of the second byte (byte 1), MSB-first: bitOffset 2 = P, 3 = F, 4 = C,
     * 5 = A, 6 = D, 7 = M (bitOffsets 0..1 are the 2-bit Session State). Decode reads it as a boolean
     * into `flags[name]`; encode writes it back — byte-for-byte identical to the hand-written pattern.
     */
    static #flagBit(name: string, bitOffset: number, label: string): ProtocolFieldJSONSchema {
        return {
            type: 'boolean',
            label: label,
            decode: function (this: BFD): void {
                (this.instance.flags as any)[name].setValue(!!this.readBits(1, 1, bitOffset, 1))
            },
            encode: function (this: BFD): void {
                const value: boolean = !!(this.instance.flags as any)[name].getValue()
                ;(this.instance.flags as any)[name].setValue(value)
                this.writeBits(1, 1, bitOffset, 1, value ? 1 : 0)
            }
        }
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'BFD state=${flags.state} mult=${detectMult}',
            properties: {
                //Byte 0: Version (top 3 bits, = 1 for RFC 5880) + Diagnostic (low 5 bits). MSB-first,
                //so version is bitOffset 0..2 and diagnostic bitOffset 3..7 of a 1-octet window.
                version: {
                    type: 'integer',
                    label: 'Version',
                    minimum: 0,
                    maximum: 7,
                    decode: function (this: BFD): void { this.instance.version.setValue(this.readBits(0, 1, 0, 3)) },
                    encode: function (this: BFD): void { this.writeBits(0, 1, 0, 3, this.instance.version.getValue(1)) }
                },
                diagnostic: {
                    type: 'integer',
                    label: 'Diagnostic',
                    minimum: 0,
                    maximum: 31,
                    decode: function (this: BFD): void { this.instance.diagnostic.setValue(this.readBits(0, 1, 3, 5)) },
                    encode: function (this: BFD): void { this.writeBits(0, 1, 3, 5, this.instance.diagnostic.getValue(0)) }
                },
                //Byte 1: 2-bit Session State + six single-bit flags (P F C A D M), MSB-first.
                flags: {
                    type: 'object',
                    label: 'Flags',
                    properties: {
                        state: {
                            type: 'integer',
                            label: 'Session State',
                            minimum: 0,
                            maximum: 3,
                            decode: function (this: BFD): void { this.instance.flags.state.setValue(this.readBits(1, 1, 0, 2)) },
                            encode: function (this: BFD): void { this.writeBits(1, 1, 0, 2, this.instance.flags.state.getValue(0)) }
                        },
                        poll: this.#flagBit('poll', 2, 'Poll'),
                        final: this.#flagBit('final', 3, 'Final'),
                        controlPlaneIndependent: this.#flagBit('controlPlaneIndependent', 4, 'Control Plane Independent'),
                        authPresent: this.#flagBit('authPresent', 5, 'Authentication Present'),
                        demand: this.#flagBit('demand', 6, 'Demand'),
                        multipoint: this.#flagBit('multipoint', 7, 'Multipoint')
                    }
                },
                detectMult: this.fieldUInt('detectMult', 2, 1, 'Detect Mult'),
                //Length of the entire BFD Control packet in bytes. Honoured verbatim (a real no-auth
                //packet carries 24) — not recomputed, so a captured packet re-encodes byte-for-byte.
                length: this.fieldUInt('length', 3, 1, 'Length'),
                myDiscriminator: this.fieldUInt('myDiscriminator', 4, 4, 'My Discriminator'),
                yourDiscriminator: this.fieldUInt('yourDiscriminator', 8, 4, 'Your Discriminator'),
                desiredMinTxInterval: this.fieldUInt('desiredMinTxInterval', 12, 4, 'Desired Min TX Interval'),
                requiredMinRxInterval: this.fieldUInt('requiredMinRxInterval', 16, 4, 'Required Min RX Interval'),
                requiredMinEchoRxInterval: this.fieldUInt('requiredMinEchoRxInterval', 20, 4, 'Required Min Echo RX Interval'),
                //Optional Authentication Section (present only when the A flag is set). Kept verbatim so
                //any auth type (simple password, keyed MD5/SHA1, meticulous) round-trips byte-for-byte;
                //bounded by the UDP datagram. Runs after `flags` so authPresent is known.
                authSection: {
                    type: 'string',
                    label: 'Authentication Section',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: BFD): void {
                        const authPresent: boolean = !!this.instance.flags.authPresent.getValue()
                        const available: number = this.#payloadLength()
                        if (!authPresent || available <= 24) {
                            this.instance.authSection.setValue('')
                            return
                        }
                        //The auth section runs to the BFD Length (which includes it) when Length is sane;
                        //anything past that inside the UDP datagram is trailing padding, left to raw (so
                        //the A-set path matches the A-clear path, which routes such bytes to a raw layer).
                        const length: number = this.instance.length.getValue(0)
                        const authLength: number = (length >= 24 && length <= available) ? length - 24 : available - 24
                        this.instance.authSection.setValue(authLength > 0 ? BufferToHex(this.readBytes(24, authLength)) : '')
                    },
                    encode: function (this: BFD): void {
                        const authSection: string = this.instance.authSection.getValue('')
                        if (authSection) this.writeBytes(24, HexToBuffer(authSection))
                    }
                }
            }
        }
    }

    public readonly id: string = 'bfd'

    public readonly name: string = 'Bidirectional Forwarding Detection'

    public readonly nickname: string = 'BFD'

    public readonly matchKeys: string[] = ['udpport:3784', 'udpport:4784']

    public match(): boolean {
        //Require the 24-byte mandatory section within the UDP payload (a shorter datagram on the BFD
        //ports is not a BFD Control packet and must fall through to raw rather than claim a layer).
        return !!this.prevCodecModule && this.prevCodecModule.id === 'udp' && this.#payloadLength() >= 24
    }

    //A leaf header — nothing is carried on top of a BFD Control packet.
    public readonly demuxProducers: DemuxProducer[] = []

}
