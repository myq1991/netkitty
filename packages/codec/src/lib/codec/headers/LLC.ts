import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../../helper/BufferToHex'
import {HexToBuffer} from '../../helper/HexToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/**
 * LLC — IEEE 802.2 Logical Link Control, the header of an IEEE 802.3 (length-encapsulated) Ethernet
 * frame. In an Ethernet II frame bytes 12–13 are an EtherType (always ≥ 0x0600); in an 802.3 frame they
 * are instead a *length* (≤ 0x05DC = 1500), and the frame payload begins with this 3-or-4-byte LLC
 * header: a 1-byte DSAP (Destination Service Access Point), a 1-byte SSAP (Source SAP), and a Control
 * field that is 1 byte for U-format (its two low bits are 0b11) or 2 bytes for I/S-format.
 *
 * LLC is a content-heuristic child of Ethernet (and 802.1Q): it claims a frame only when the parent's
 * EtherType value is ≤ 0x05DC, which by construction can never be a real EtherType — so the Ethernet II
 * path is completely untouched. It carries no length of its own; the child it routes to (STP by DSAP
 * 0x42, IS-IS by 0xFE, or SNAP by 0xAA which re-exposes an EtherType) bounds itself, and any trailing
 * 802.3 minimum-frame padding falls to the codec's RawData catch-all. The DSAP is exposed as an `llcsap`
 * demux key. A well-formed frame round-trips byte-for-byte.
 */
export class LLC extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (LLC.#schemaCache ??= LLC.#buildSchema())
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'LLC dsap=${dsap} ssap=${ssap}',
            properties: {
                //Destination Service Access Point — the field the `llcsap` demux key is produced from.
                //Kept as the raw byte (not masked for the I/G bit) so it re-emits exactly and 0x42/0xAA/0xFE
                //route unambiguously.
                dsap: this.fieldUInt('dsap', 0, 1, 'DSAP'),
                ssap: this.fieldUInt('ssap', 1, 1, 'SSAP'),
                //Control: 1 byte for Unnumbered format (low two bits 0b11), else 2 bytes (Information /
                //Supervisory). Stored as hex preserving its on-wire length so encode reproduces it exactly;
                //because the non-dry read grows headerLength, the child layer starts at the correct offset.
                control: {
                    type: 'string',
                    label: 'Control',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: LLC): void {
                        const first: number = this.readBytes(2, 1, true)[0]
                        const length: number = (first & 0x03) === 0x03 ? 1 : 2
                        this.instance.control.setValue(BufferToHex(this.readBytes(2, length)))
                    },
                    encode: function (this: LLC): void {
                        //Default to a U-format UI control (0x03) when crafting without a supplied value.
                        const control: string = this.instance.control.getValue('03')
                        this.writeBytes(2, HexToBuffer(control && control.length >= 2 ? control : '03'))
                    }
                }
            }
        }
    }

    public readonly id: string = 'llc'

    public readonly name: string = 'Logical Link Control'

    public readonly nickname: string = 'LLC'

    //A content-heuristic child (no matchKeys) — claimed when the Ethernet/VLAN parent's EtherType is a
    //length (≤ 0x05DC), which cannot be a real EtherType.
    public readonly matchKeys: string[] = []

    public readonly demuxProducers: DemuxProducer[] = [{field: 'dsap', namespace: 'llcsap', kind: 'uint'}]

    public match(): boolean {
        const prev: any = this.prevCodecModule
        if (!prev || (prev.id !== 'eth' && prev.id !== 'vlan')) return false
        //IEEE 802.3: bytes 12–13 ≤ 1500 (0x05DC) are a length → an 802.3/LLC frame. Valid EtherTypes are
        //all ≥ 0x0600, so this gate never claims an Ethernet II frame (the 1501–1535 gap is left to raw,
        //matching prior behavior). Require at least the 3-byte minimum LLC header.
        const value: number = parseInt(prev.instance.etherType.getValue(''), 16)
        if (!(value >= 0 && value <= 0x05dc)) return false
        return this.packet.length - this.startPos >= 3
    }

}
