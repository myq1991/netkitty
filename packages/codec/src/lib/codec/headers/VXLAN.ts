import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'

/**
 * VXLAN — Virtual eXtensible LAN (RFC 7348), a Layer-2-over-UDP overlay on UDP port 4789. An 8-byte
 * header — Flags(1, the 'I' bit marks the VNI valid), 3 reserved bytes, the 24-bit VNI (VXLAN Network
 * Identifier), and 1 reserved byte — is followed by a COMPLETE inner Ethernet frame.
 *
 * This codec decodes only its own 8-byte header (headerLength = 8); the inner Ethernet frame is left to
 * the codec's normal recursion, which decodes it as a fresh eth/ip/… stack. That works because
 * EthernetII.match() already accepts a tunnel (vxlan/gre/geneve/…) as its parent — the demux
 * generalization anticipates tunnels — so an inner Ethernet frame after VXLAN is dispatched to
 * EthernetII automatically. The whole nested packet round-trips byte-for-byte layer by layer.
 */
export class VXLAN extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (VXLAN.#schemaCache ??= VXLAN.#buildSchema())
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'VXLAN vni=${vni}',
            properties: {
                flags: this.fieldUInt('flags', 0, 1, 'Flags'),
                reserved1: this.fieldHex('reserved1', 1, 3, 'Reserved'),
                vni: {
                    type: 'integer',
                    label: 'VNI',
                    minimum: 0,
                    maximum: 16777215,
                    decode: function (this: VXLAN): void {
                        this.instance.vni.setValue(this.readBits(4, 3, 0, 24))
                    },
                    encode: function (this: VXLAN): void {
                        let vni: number = this.instance.vni.getValue(0)
                        if (vni > 16777215) {
                            this.recordError(this.instance.vni.getPath(), 'Maximum value is 16777215')
                            vni = 16777215
                        }
                        if (vni < 0) {
                            this.recordError(this.instance.vni.getPath(), 'Minimum value is 0')
                            vni = 0
                        }
                        this.instance.vni.setValue(vni)
                        this.writeBits(4, 3, 0, 24, vni)
                    }
                },
                reserved2: this.fieldHex('reserved2', 7, 1, 'Reserved')
            }
        }
    }

    public readonly id: string = 'vxlan'

    public readonly name: string = 'Virtual eXtensible Local Area Network'

    public readonly nickname: string = 'VXLAN'

    public readonly matchKeys: string[] = ['udpport:4789']

    public match(): boolean {
        if (!this.prevCodecModule || this.prevCodecModule.id !== 'udp') return false
        //Require the 8-byte header within the UDP payload (not just the captured frame — see RADIUS).
        let available: number = this.packet.length - this.startPos
        const udpLength: number = this.prevCodecModule.instance.length.getValue(0)
        if (udpLength >= 8 && udpLength - 8 < available) available = udpLength - 8
        return available >= 8
    }

    //Produces no demux key of its own; the inner Ethernet frame is matched by EthernetII's tunnel-aware
    //match() (which lists 'vxlan' as an accepted parent), so recursion decodes the inner stack.
    public readonly demuxProducers: DemuxProducer[] = []

}
