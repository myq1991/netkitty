import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {BaseHeader} from '../abstracts/BaseHeader'
import {UInt16ToHex} from '../../helper/NumberToHex'
import {BufferToHex} from '../../helper/BufferToHex'

export class VLAN_802dot1Q extends BaseHeader {
    public SCHEMA: ProtocolJSONSchema = {
        type: 'object',
        properties: {
            priority: {
                type: 'integer',
                minimum: 0,
                maximum: 7,
                default: 0,
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
                decode: (): void => {
                    this.instance.etherType.setValue(BufferToHex(this.readBytes(2, 2)))
                },
                encode: (): void => {
                    let etherType: string = this.instance.etherType.getValue(UInt16ToHex(0x0000), (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                    const typeBuffer: Buffer = Buffer.from(etherType, 'hex')
                    if (typeBuffer.length < 2) typeBuffer.fill(0, 0, 1)
                    this.writeBytes(2, typeBuffer.subarray(0, 2))
                }
            }
        }
    }

    public readonly id: string = 'vlan'

    public readonly name: string = '802.1Q Virtual LAN'

    public readonly nickname: string = 'VLAN'

    public match(): boolean {
        if (!this.prevCodecModule) return false
        return this.prevCodecModule.instance.etherType.getValue() === UInt16ToHex(0x8100)
    }
}
