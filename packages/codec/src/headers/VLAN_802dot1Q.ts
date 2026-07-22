import {ProtocolJSONSchema} from '../schema/ProtocolJSONSchema'
import {BaseHeader} from '../abstracts/BaseHeader'
import {DemuxProducer} from '../types/DemuxProducer'
import {UInt16ToHex} from '../helper/NumberToHex'
import {BufferToHex} from '../helper/BufferToHex'

/**
 * VLAN 802.1Q — the IEEE 802.1Q VLAN tag, selected when the carrying layer's EtherType is the TPID 0x8100.
 * This codec decodes the 4-octet tag that follows the TPID: the 2-octet Tag Control Information split into
 * a 3-bit Priority / PCP (`priority`, top bits of offset 0), a 1-bit Drop Eligible Indicator (`dei`,
 * boolean) and a 12-bit VLAN ID (`id`, the low 12 bits), followed by the 16-bit EtherType of the
 * encapsulated frame (`etherType`, offset 2, a lowercase 4-hex string).
 *
 * The trailing `etherType` is published as an `ethertype` demux key so the tagged inner protocol
 * (IPv4/IPv6/ARP, another VLAN for QinQ, GOOSE, SV…) is selected exactly as it would be off bare Ethernet.
 * match() fires whenever the parent's EtherType is 0x8100, regardless of which layer carries it, so it
 * handles both single- and stacked-tag frames.
 */
export class VLAN_802dot1Q extends BaseHeader {
    public SCHEMA: ProtocolJSONSchema = {
        type: 'object',
        properties: {
            priority: {
                type: 'integer',
                minimum: 0,
                maximum: 7,
                default: 0,
                label: 'Priority',
                decode: (): void => {
                    this.instance.priority.setValue(this.readBits(0, 2, 0, 3))
                },
                encode: (): void => {
                    const priorityValue: number = this.instance.priority.getValue(0)
                    this.instance.priority.setValue(priorityValue)
                    this.writeBits(0, 2, 0, 3, priorityValue)
                }
            },
            dei: {
                type: 'boolean',
                label: 'DEI',
                decode: (): void => {
                    this.instance.dei.setValue(!!this.readBits(0, 2, 3, 1))
                },
                encode: (): void => {
                    const dei: boolean = !!this.instance.dei.getValue()
                    this.instance.dei.setValue(dei)
                    this.writeBits(0, 2, 3, 1, dei ? 1 : 0)
                }
            },
            id: {
                type: 'integer',
                minimum: 0,
                maximum: 4095,
                label: 'ID',
                decode: (): void => {
                    this.instance.id.setValue(this.readBits(0, 2, 4, 12))
                },
                encode: (): void => {
                    const vlanId: number = this.instance.id.getValue(0)
                    this.instance.id.setValue(vlanId)
                    this.writeBits(0, 2, 4, 12, vlanId)
                }
            },
            etherType: {
                type: 'string',
                minLength: 4,
                maxLength: 4,
                label: 'EtherType',
                decode: (): void => {
                    this.instance.etherType.setValue(BufferToHex(this.readBytes(2, 2)))
                },
                encode: (): void => {
                    const etherType: string = this.instance.etherType.getValue(UInt16ToHex(0x0000), (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                    const typeBuffer: Buffer = Buffer.from(etherType, 'hex')
                    if (typeBuffer.length < 2) typeBuffer.fill(0, 0, 1)
                    this.writeBytes(2, typeBuffer.subarray(0, 2))
                }
            }
        }
    }

    public readonly id: string = 'vlan'

    public readonly matchKeys: string[] = ['ethertype:8100']

    public readonly demuxProducers: DemuxProducer[] = [{field: 'etherType', namespace: 'ethertype', kind: 'string'}]

    public readonly name: string = '802.1Q Virtual LAN'

    public readonly nickname: string = 'VLAN'

    public match(): boolean {
        if (!this.prevCodecModule) return false
        return this.prevCodecModule.instance.etherType.getValue() === UInt16ToHex(0x8100)
    }
}
