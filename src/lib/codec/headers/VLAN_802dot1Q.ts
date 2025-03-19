import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {BaseHeader} from '../lib/BaseHeader'
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
                    //TODO
                }
            },
            dei: {
                type: 'boolean',
                decode: (): void => {
                    this.instance.dei = !!this.readBits(0, 2, 3, 1)
                },
                encode: (): void => {
                    //TODO
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
                    //TODO
                }
            },
            type: {
                type: 'string',
                decode: (): void => {
                    this.instance.type = `0x${this.readBytes(2, 2).toString('hex').padStart(4, '0')}`
                },
                encode: (): void => {
                    //TODO
                }
            }
        }
    }
    public id: string = 'vlan'

    public name: string = '802.1Q Virtual LAN'

    public match(prevCodecModule?: CodecModule): boolean {
        if (!prevCodecModule) return false
        return prevCodecModule.instance.type === '0x8100'
    }
}
