import {BaseHeader} from '../lib/BaseHeader'
import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {CodecModule} from '../types/CodecModule'

export default class Ethernet_II extends BaseHeader {

    public readonly id: string = 'eth'

    public readonly name: string = 'Ethernet II'

    public readonly SCHEMA: ProtocolJSONSchema = {
        properties: {
            dst: {
                type: 'string',
                minLength: 17,
                maxLength: 17,
                decode: (): void => {
                    this.instance.dst = Array.from(this.readBytes(0, 6)).map(value => value.toString(16).padStart(2, '0')).join(':')
                },
                encode: (): void => {

                }
            },
            src: {
                type: 'string',
                minLength: 17,
                maxLength: 17,
                decode: (): void => {
                    this.instance.src = Array.from(this.readBytes(6, 6)).map(value => value.toString(16).padStart(2, '0')).join(':')
                },
                encode: (): void => {
                    //TODO
                }
            },
            type: {
                type: 'string',
                decode: (): void => {
                    this.instance.type = `0x${this.readBytes(12, 2).toString('hex').padStart(4, '0')}`
                },
                encode: (): void => {
                    //TODO
                }
            }
        }
    }

    public match(prevCodecModule?: CodecModule): boolean {
        const specialScenes: string[] = ['trill', 'vxlan', 'nvgre', 'mpls', 'qinq', 'gre', 'geneve']
        if (prevCodecModule && !specialScenes.includes(prevCodecModule.id)) return false
        return true
    }
}
