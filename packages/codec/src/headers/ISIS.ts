import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../helper/BufferToHex'
import {HexToBuffer} from '../helper/HexToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/**
 * IS-IS — Intermediate System to Intermediate System routing (ISO/IEC 10589), carried in an 802.3 frame
 * over LLC with DSAP/SSAP 0xFE. Every PDU opens with an 8-byte common header: the Intradomain Routing
 * Protocol Discriminator (0x83), a Length Indicator (the header length), a Version/Protocol Id Extension,
 * an ID Length, a 1-byte PDU Type (its low 5 bits; upper 3 reserved), a Version, a reserved byte and the
 * Maximum Area Addresses.
 *
 * The PDU-type-specific part (Hello / LSP / CSNP / PSNP fixed fields + TLVs) is kept verbatim as `body`
 * hex — it is rich and type-dependent — bounded by the captured bytes. PDU types: 15 L1 LAN Hello, 16
 * L2 LAN Hello, 17 Point-to-Point Hello, 18 L1 LSP, 20 L2 LSP, 24/25 L1/L2 CSNP, 26/27 L1/L2 PSNP. A
 * well-formed PDU round-trips byte-for-byte.
 */
export class ISIS extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (ISIS.#schemaCache ??= ISIS.#buildSchema())
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'IS-IS type=${pduType}',
            properties: {
                irpDiscriminator: this.fieldHex('irpDiscriminator', 0, 1, 'IRP Discriminator'),
                lengthIndicator: this.fieldUInt('lengthIndicator', 1, 1, 'Length Indicator'),
                versionProtocolIdExtension: this.fieldUInt('versionProtocolIdExtension', 2, 1, 'Version/Protocol Id Extension'),
                idLength: this.fieldUInt('idLength', 3, 1, 'ID Length'),
                pduType: this.fieldUInt('pduType', 4, 1, 'PDU Type'),
                version: this.fieldUInt('version', 5, 1, 'Version'),
                reserved: this.fieldUInt('reserved', 6, 1, 'Reserved'),
                maximumAreaAddresses: this.fieldUInt('maximumAreaAddresses', 7, 1, 'Maximum Area Addresses'),
                //The PDU-type-specific fixed fields + TLVs, kept verbatim. Bounded by the captured bytes so
                //trailing 802.3 padding is left to RawData.
                body: {
                    type: 'string',
                    label: 'Body',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: ISIS): void {
                        const available: number = this.packet.length - this.startPos
                        this.instance.body.setValue(available > 8 ? BufferToHex(this.readBytes(8, available - 8)) : '')
                    },
                    encode: function (this: ISIS): void {
                        const body: string = this.instance.body.getValue('')
                        if (body) this.writeBytes(8, HexToBuffer(body))
                    }
                }
            }
        }
    }

    public readonly id: string = 'isis'

    public readonly name: string = 'Intermediate System to Intermediate System'

    public readonly nickname: string = 'IS-IS'

    public readonly matchKeys: string[] = ['llcsap:254']

    public match(): boolean {
        //An LLC child selected by DSAP 0xFE (254). Confirm the parent is LLC with DSAP 0xFE, the 0x83
        //discriminator, and the 8-byte common header.
        const prev: any = this.prevCodecModule
        if (!prev || prev.id !== 'llc') return false
        if (prev.instance.dsap.getValue(0) !== 0xfe) return false
        if (this.packet.length - this.startPos < 8) return false
        return this.readBytes(0, 1, true)[0] === 0x83
    }

    //A leaf for this slice — the type-specific fields and TLVs are kept verbatim.
    public readonly demuxProducers: DemuxProducer[] = []

}
