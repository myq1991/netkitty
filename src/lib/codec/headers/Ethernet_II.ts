import {BaseHeader} from '../lib/BaseHeader'
import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {CodecModule} from '../types/CodecModule'

export default class Ethernet_II extends BaseHeader {

    public readonly id: string = 'eth'

    public readonly name: string = 'Ethernet II'

    public readonly SCHEMA: ProtocolJSONSchema = {
        properties: {
            dmac: {
                type: 'string',
                minLength: 17,
                maxLength: 17,
                decode: (): void => {
                    this.instance.dmac = Array.from(this.readBytes(0, 6)).map(value => value.toString(16).padStart(2, '0')).join(':')
                },
                encode: (): void => {
                    const dmac: number[] = this.instance.dmac.toString().split(':').map(value => parseInt(value, 16)).map(value => value ? value : 0)
                    this.writeBytes(0, Buffer.alloc(6, Buffer.from(dmac)))
                }
            },
            smac: {
                type: 'string',
                minLength: 17,
                maxLength: 17,
                decode: (): void => {
                    this.instance.smac = Array.from(this.readBytes(6, 6)).map(value => value.toString(16).padStart(2, '0')).join(':')
                },
                encode: (): void => {
                    const smac: number[] = this.instance.smac.toString().split(':').map(value => parseInt(value, 16)).map(value => value ? value : 0)
                    this.writeBytes(6, Buffer.alloc(6, Buffer.from(smac)))
                }
            },
            etherType: {
                type: 'string',
                decode: (): void => {
                    this.instance.etherType = `0x${this.readBytes(12, 2).toString('hex').padStart(4, '0')}`
                },
                encode: (): void => {
                    const hexEtherType: string = this.instance.etherType ? this.instance.etherType.toString() : '0x0000'
                    let etherType: number = parseInt(hexEtherType, 16)
                    etherType = etherType ? etherType : 0
                    const typeBuffer: Buffer = Buffer.from(etherType.toString(16), 'hex')
                    if (typeBuffer.length < 2) typeBuffer.fill(0, 0, 1)
                    this.writeBytes(12, typeBuffer.subarray(0, 2))
                }
            }
        }
    }

    public match(prevCodecModule: CodecModule): boolean {
        const specialScenes: string[] = ['trill', 'vxlan', 'nvgre', 'mpls', 'qinq', 'gre', 'geneve']
        if (prevCodecModule && !specialScenes.includes(prevCodecModule.id)) return false
        return true
    }
}
