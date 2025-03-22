import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {BaseHeader} from '../abstracts/BaseHeader'
import {CodecModule} from '../types/CodecModule'

export default class VLAN_802dot1Q extends BaseHeader {
    public SCHEMA: ProtocolJSONSchema = {
        properties: {
            priority: {
                type: 'integer',
                minimum: 0,
                maximum: 7,
                default: 0,
                decode: (): void => {
                    this.instance.priority = this.readBits(0, 2, 0, 3)
                },
                encode: (): void => {
                    let priorityValue: number = parseInt(this.instance.priority.toString())
                    priorityValue = priorityValue ? priorityValue : 0
                    this.writeBits(0, 2, 0, 3, priorityValue)
                }
            },
            dei: {
                type: 'boolean',
                decode: (): void => {
                    this.instance.dei = !!this.readBits(0, 2, 3, 1)
                },
                encode: (): void => {
                    this.writeBits(0, 2, 3, 1, !!this.instance.dei ? 1 : 0)
                }
            },
            id: {
                type: 'integer',
                minimum: 0,
                maximum: 4095,
                decode: (): void => {
                    this.instance.id = this.readBits(0, 2, 4, 12)
                },
                encode: (): void => {
                    let vlanId: number = parseInt(this.instance.id.toString())
                    this.writeBits(0, 2, 4, 12, vlanId ? vlanId : 0)
                }
            },
            etherType: {
                type: 'integer',
                minimum: 0x0600,
                maximum: 0xffff,
                decode: (): void => {
                    this.instance.etherType = parseInt(this.readBytes(2, 2).toString('hex'), 16)
                },
                encode: (): void => {
                    let etherType: number = this.instance.etherType ? parseInt(this.instance.etherType.toString()) : 0x0000
                    etherType = etherType ? etherType : 0
                    const typeBuffer: Buffer = Buffer.from(etherType.toString(16), 'hex')
                    if (typeBuffer.length < 2) typeBuffer.fill(0, 0, 1)
                    this.writeBytes(2, typeBuffer.subarray(0, 2))
                }
            }
        }
    }

    public id: string = 'vlan'

    public name: string = '802.1Q Virtual LAN'

    public match(): boolean {
        if (!this.prevCodecModule) return false
        return this.prevCodecModule.instance.etherType === 0x8100
    }
}
