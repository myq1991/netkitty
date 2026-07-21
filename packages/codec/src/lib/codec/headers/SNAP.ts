import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'

/**
 * SNAP — Sub-Network Access Protocol (IEEE 802.2), the 5-byte header that follows an LLC header whose
 * DSAP/SSAP are 0xAA. It carries a 3-byte OUI (Organizationally Unique Identifier) and a 2-byte Protocol
 * Identifier. When the OUI is 0x000000 the PID is an EtherType, so SNAP re-exposes it (in a field named
 * `etherType`, identically to Ethernet/VLAN) and routes IPv4/ARP/IPv6/… through the existing `ethertype`
 * demux for free. A non-zero OUI (e.g. Cisco 0x00000C for CDP/VTP) is a vendor protocol whose PID is not
 * an EtherType; for those SNAP also emits an `snapoui` key of OUI+PID concatenated. A well-formed SNAP
 * header round-trips byte-for-byte.
 */
export class SNAP extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (SNAP.#schemaCache ??= SNAP.#buildSchema())
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'SNAP oui=${oui} type=${etherType}',
            properties: {
                oui: this.fieldHex('oui', 0, 3, 'OUI'),
                //Named `etherType` (not `pid`) so the existing ethertype demux + IPv4/ARP/IPv6 match() —
                //which read the parent's `etherType` field literally — route through SNAP unchanged, exactly
                //as they do through Ethernet II and 802.1Q.
                etherType: this.fieldHex('etherType', 3, 2, 'Protocol Type'),
                //Display/demux-only: OUI+PID concatenated, the `snapoui` key for vendor protocols (CDP/VTP
                //under Cisco 0x00000C). No encode closure — the bytes are written by oui + etherType, this
                //is derived — so it never affects the re-emitted frame.
                ouiProtocol: {
                    type: 'string',
                    label: 'OUI Protocol',
                    decode: function (this: SNAP): void {
                        const oui: string = this.instance.oui.getValue('')
                        const etherType: string = this.instance.etherType.getValue('')
                        this.instance.ouiProtocol.setValue((oui + etherType).toLowerCase())
                    }
                }
            }
        }
    }

    public readonly id: string = 'snap'

    public readonly name: string = 'Sub-Network Access Protocol'

    public readonly nickname: string = 'SNAP'

    public readonly matchKeys: string[] = ['llcsap:170']

    public match(): boolean {
        //An LLC child selected by DSAP 0xAA (170). Confirm the parent is LLC with DSAP 0xAA and the full
        //5-byte SNAP header is present.
        const prev: any = this.prevCodecModule
        if (!prev || prev.id !== 'llc') return false
        if (prev.instance.dsap.getValue(0) !== 0xaa) return false
        return this.packet.length - this.startPos >= 5
    }

    //Two producers: the EtherType (for OUI 0x000000 → the shared ethertype machinery) and the OUI+PID
    //(for vendor protocols → the snapoui namespace). Both are emitted; the miss simply never matches.
    public readonly demuxProducers: DemuxProducer[] = [
        {field: 'etherType', namespace: 'ethertype', kind: 'string'},
        {field: 'ouiProtocol', namespace: 'snapoui', kind: 'string'}
    ]

}
