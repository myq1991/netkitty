import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../../helper/BufferToHex'
import {HexToBuffer} from '../../helper/HexToBuffer'

/**
 * CMS — the China smart-substation "next-generation communication" protocol (DL/T 860 CMS family), a
 * State-Grid replacement for IEC 61850 MMS that maps ACSI directly onto TCP (port 8102), dropping the
 * OSI upper layers (no TPKT/COTP/Session/Presentation). There is no freely-available authoritative
 * specification, so this codec is reverse-engineered from real captured traffic (plaintext CMS on
 * tcp:8102): every PDU begins with a 4-byte frame header — a 1-byte flags octet whose 0x40 bit marks a
 * response (0x01 request / 0x41 response), a 1-byte service type (0x9a associate, 0x9b get-data, …), and
 * a 2-byte little-endian Length of the ACSI PDU that follows.
 *
 * The ACSI PDU body is kept verbatim as `body` hex — its deeper structure (PER/ASN.1-like) is a later
 * slice. A CMS PDU can exceed one TCP segment; this single-packet stateless codec structures the frame
 * header and the body bytes present in THIS packet (bounded by the captured payload), leaving stream
 * reassembly to a higher layer — continuation segments (which do not begin with 0x01/0x41) are not
 * claimed as CMS and fall to raw. A single-segment frame round-trips byte-for-byte.
 */
export class CMS extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (CMS.#schemaCache ??= CMS.#buildSchema())
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'CMS service=${serviceType} flags=${flags}',
            properties: {
                //Flags octet: 0x01 request / 0x41 response (bit 0x40 = response direction). Kept verbatim.
                flags: this.fieldUInt('flags', 0, 1, 'Flags'),
                //Service type: 0x9a associate, 0x9b get-data, 0x01 …
                serviceType: this.fieldUInt('serviceType', 1, 1, 'Service Type'),
                //2-byte LITTLE-ENDIAN length of the ACSI PDU body. Honored verbatim.
                length: {
                    type: 'integer', label: 'Length', minimum: 0, maximum: 65535,
                    decode: function (this: CMS): void {
                        const bytes: Buffer = this.readBytes(2, 2)
                        this.instance.length.setValue((bytes[0] | (bytes[1] << 8)) & 0xffff)
                    },
                    encode: function (this: CMS): void {
                        let value: number = this.instance.length.getValue(0)
                        if (value > 65535) value = 65535
                        if (value < 0) value = 0
                        this.writeBytes(2, Buffer.from([value & 0xff, (value >> 8) & 0xff]))
                    }
                },
                //The ACSI PDU, kept verbatim. Bounded by the frame's Length and the captured bytes — for a
                //PDU segmented across TCP segments only the bytes present in this packet are captured; the
                //rest is left to a higher reassembly layer.
                body: {
                    type: 'string', label: 'Body', contentEncoding: 'hex',
                    decode: function (this: CMS): void {
                        const available: number = this.packet.length - this.startPos
                        const declared: number = this.instance.length.getValue(0)
                        let end: number = 4 + declared
                        if (end > available) end = available
                        this.instance.body.setValue(end > 4 ? BufferToHex(this.readBytes(4, end - 4)) : '')
                    },
                    encode: function (this: CMS): void {
                        const body: string = this.instance.body.getValue('')
                        if (body) this.writeBytes(4, HexToBuffer(body))
                    }
                }
            }
        }
    }

    public readonly id: string = 'cms'

    public readonly name: string = 'CMS (China Smart-Substation Communication)'

    public readonly nickname: string = 'CMS'

    public readonly matchKeys: string[] = ['tcpport:8102']

    public match(): boolean {
        //CMS rides on TCP port 8102. Require the 4-byte frame header and the request/response flags
        //signature (0x01 / 0x41) so non-CMS traffic and mid-PDU continuation segments (which begin with
        //ACSI data bytes, not 0x01/0x41) fall through to raw.
        if (!this.prevCodecModule || this.prevCodecModule.id !== 'tcp') return false
        if (this.packet.length - this.startPos < 4) return false
        const flags: number = this.readBytes(0, 1, true)[0]
        return flags === 0x01 || flags === 0x41
    }

    //A leaf for this slice — the ACSI PDU body is kept verbatim (deeper structure is a later slice).
    public readonly demuxProducers: DemuxProducer[] = []

}
