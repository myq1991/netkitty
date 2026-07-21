import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {ProtocolFieldJSONSchema} from '../../schema/ProtocolFieldJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../../helper/BufferToHex'
import {HexToBuffer} from '../../helper/HexToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/**
 * MACsec — MAC Security (IEEE 802.1AE), carried directly in an Ethernet II frame with EtherType 0x88E5
 * (an Ethernet child — no IP/UDP). Each frame carries a Security TAG (SecTAG) followed by the secured
 * user data and a trailing Integrity Check Value (ICV).
 *
 * The SecTAG is 6 or 14 octets:
 *   - byte 0: TCI (TAG Control Information, high 6 bits) + AN (Association Number, low 2 bits). The TCI
 *     bits, MSB-first, are V (Version), ES (End Station), SC (SCI present), SCB (Single Copy Broadcast),
 *     E (Encryption), C (Changed text).
 *   - byte 1: SL (Short Length) — the secured-data octet count when it is < 48, else 0. Informational
 *     here; it does not bound the secured data (the ICV does).
 *   - bytes 2..5: PN (Packet Number) — big-endian 32-bit anti-replay counter.
 *   - bytes 6..13: SCI (Secure Channel Identifier) — 8 octets, present only when the SC bit is set.
 *
 * After the SecTAG comes the secured data (the original frame's user data — encrypted when the E bit is
 * set, otherwise authenticated cleartext) and a fixed 16-octet ICV at the very end of the frame. Without
 * the SA keys the secured region cannot be split, so — like ESP — MACsec is a leaf: the SecTAG fields are
 * surfaced and the secured data + ICV are kept verbatim as hex. The secured data spans from the end of
 * the SecTAG to the last 16 octets (the ICV); nothing is recomputed on encode (a faithful executor
 * carries the ciphertext and ICV as-is), so a well-formed MACsec frame round-trips byte-for-byte.
 */
export class MACsec extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (MACsec.#schemaCache ??= MACsec.#buildSchema())
    }

    /** SecTAG length: 6 octets, plus the 8-octet SCI when the SC bit (byte 0, bit 5 MSB-first) is set. */
    #sectagLength(): number {
        return this.instance.sc.getValue(0) ? 14 : 6
    }

    /**
     * A field packed into the first SecTAG octet (byte 0): `bitLength` bits at `bitOffset` (MSB-first).
     * Decode reads it into `name`; encode clamps to the field's range (recording an error, never
     * throwing) and overlays it via writeBits — each sub-field masks its own bits so they never clobber.
     */
    static #fieldBits(name: string, bitOffset: number, bitLength: number, label: string): ProtocolFieldJSONSchema {
        const maximum: number = (1 << bitLength) - 1
        return {
            type: 'integer',
            label: label,
            minimum: 0,
            maximum: maximum,
            decode: function (this: MACsec): void {
                (this.instance as any)[name].setValue(this.readBits(0, 1, bitOffset, bitLength))
            },
            encode: function (this: MACsec): void {
                const node: any = (this.instance as any)[name]
                let value: number = node.getValue(0, (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                if (value > maximum) {
                    this.recordError(node.getPath(), `Maximum value is ${maximum}`)
                    value = maximum
                }
                if (value < 0) {
                    this.recordError(node.getPath(), 'Minimum value is 0')
                    value = 0
                }
                node.setValue(value)
                this.writeBits(0, 1, bitOffset, bitLength, value)
            }
        }
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'MACsec an=${an} pn=${packetNumber}',
            properties: {
                //TCI (TAG Control Information) — the high 6 bits of SecTAG byte 0, MSB-first, then AN.
                version: this.#fieldBits('version', 0, 1, 'Version (V)'),
                es: this.#fieldBits('es', 1, 1, 'End Station (ES)'),
                sc: this.#fieldBits('sc', 2, 1, 'SCI Present (SC)'),
                scb: this.#fieldBits('scb', 3, 1, 'Single Copy Broadcast (SCB)'),
                encryption: this.#fieldBits('encryption', 4, 1, 'Encryption (E)'),
                changed: this.#fieldBits('changed', 5, 1, 'Changed Text (C)'),
                //Association Number — the low 2 bits of SecTAG byte 0.
                an: this.#fieldBits('an', 6, 2, 'Association Number (AN)'),
                //Short Length — secured-data octet count when < 48, else 0. Informational; honored verbatim.
                shortLength: this.fieldUInt('shortLength', 1, 1, 'Short Length (SL)'),
                //Packet Number — big-endian 32-bit anti-replay counter.
                packetNumber: this.fieldUInt('packetNumber', 2, 4, 'Packet Number'),
                //Secure Channel Identifier — 8 octets, present only when the SC bit is set. Its presence
                //shifts the secured data / ICV by 8 octets (see #sectagLength). Normalised to 8 octets on
                //encode so the SecTAG length stays consistent with the SC bit.
                sci: {
                    type: 'string',
                    label: 'SCI',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: MACsec): void {
                        this.instance.sci.setValue(this.instance.sc.getValue(0) ? BufferToHex(this.readBytes(6, 8)) : '')
                    },
                    encode: function (this: MACsec): void {
                        if (!this.instance.sc.getValue(0)) {
                            this.instance.sci.setValue('')
                            return
                        }
                        let buffer: Buffer = HexToBuffer(this.instance.sci.getValue('0000000000000000'))
                        if (buffer.length !== 8) {
                            this.recordError(this.instance.sci.getPath(), 'SCI must be 8 octets when the SC bit is set')
                            const fixed: Buffer = Buffer.alloc(8, 0)
                            buffer.copy(fixed, 0, 0, Math.min(8, buffer.length))
                            buffer = fixed
                        }
                        this.instance.sci.setValue(BufferToHex(buffer))
                        this.writeBytes(6, buffer)
                    }
                },
                //The secured user data (encrypted when the E bit is set, else authenticated cleartext),
                //kept verbatim. Spans from the end of the SecTAG to the last 16 octets (the ICV); bounded
                //so the trailing ICV is never pulled in.
                securedData: {
                    type: 'string',
                    label: 'Secured Data',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: MACsec): void {
                        const available: number = this.packet.length - this.startPos
                        const sectag: number = this.#sectagLength()
                        let icvStart: number = available - 16
                        if (icvStart < sectag) icvStart = sectag
                        this.instance.securedData.setValue(icvStart > sectag ? BufferToHex(this.readBytes(sectag, icvStart - sectag)) : '')
                    },
                    encode: function (this: MACsec): void {
                        const data: string = this.instance.securedData.getValue('')
                        if (data) this.writeBytes(this.#sectagLength(), HexToBuffer(data))
                    }
                },
                //The Integrity Check Value — the trailing 16 octets of the frame, kept verbatim (never
                //recomputed; the SA key is out of band). Placed immediately after the secured data.
                icv: {
                    type: 'string',
                    label: 'ICV',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: MACsec): void {
                        const available: number = this.packet.length - this.startPos
                        const sectag: number = this.#sectagLength()
                        let icvStart: number = available - 16
                        if (icvStart < sectag) icvStart = sectag
                        this.instance.icv.setValue(available > icvStart ? BufferToHex(this.readBytes(icvStart, available - icvStart)) : '')
                    },
                    encode: function (this: MACsec): void {
                        const icv: string = this.instance.icv.getValue('')
                        if (icv) {
                            const dataBytes: number = HexToBuffer(this.instance.securedData.getValue('')).length
                            this.writeBytes(this.#sectagLength() + dataBytes, HexToBuffer(icv))
                        }
                    }
                }
            }
        }
    }

    public readonly id: string = 'macsec'

    public readonly name: string = 'MAC Security'

    public readonly nickname: string = 'MACsec'

    public readonly matchKeys: string[] = ['ethertype:88e5']

    public match(): boolean {
        //An Ethernet child selected by EtherType 0x88E5 (stored as a lowercase 4-hex string). Require the
        //6-octet minimum SecTAG (TCI/AN + SL + PN, no SCI) so the fixed header fields have room.
        if (!this.prevCodecModule || this.prevCodecModule.id !== 'eth') return false
        if (this.prevCodecModule.instance.etherType.getValue() !== '88e5') return false
        return this.packet.length - this.startPos >= 6
    }

    //A leaf header — the secured data is opaque without the SA keys and cannot be dissected further.
    public readonly demuxProducers: DemuxProducer[] = []

}
