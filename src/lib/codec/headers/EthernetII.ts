import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {UInt16ToHex} from '../lib/NumberToHex'

export default class EthernetII extends BaseHeader {

    public readonly id: string = 'eth'

    public readonly name: string = 'Ethernet II'

    public readonly SCHEMA: ProtocolJSONSchema = {
        properties: {
            dmac: {
                type: 'string',
                minLength: 17,
                maxLength: 17,
                label: 'Destination',
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
                label: 'Source',
                decode: (): void => {
                    this.instance.smac = Array.from(this.readBytes(6, 6)).map(value => value.toString(16).padStart(2, '0')).join(':')
                },
                encode: (): void => {
                    const smac: number[] = this.instance.smac.toString().split(':').map(value => parseInt(value, 16)).map(value => value ? value : 0)
                    this.writeBytes(6, Buffer.alloc(6, Buffer.from(smac)))
                }
            },
            etherType: {
                type: 'integer',
                minimum: 0x0600,
                maximum: 0xffff,
                label: 'EtherType',
                decode: (): void => {
                    this.instance.etherType = parseInt(this.readBytes(12, 2).toString('hex'), 16)
                },
                encode: (): void => {
                    let etherType: number = this.instance.etherType ? parseInt(this.instance.etherType.toString()) : 0x0000
                    etherType = etherType ? etherType : 0
                    const typeBuffer: Buffer = Buffer.from(UInt16ToHex(etherType), 'hex')
                    if (typeBuffer.length < 2) typeBuffer.fill(0, 0, 1)
                    this.writeBytes(12, typeBuffer.subarray(0, 2))
                }
            }
        }
    }

    public match(): boolean {
        const specialScenes: string[] = ['trill', 'vxlan', 'nvgre', 'mpls', 'qinq', 'gre', 'geneve']
        if (this.prevCodecModule && !specialScenes.includes(this.prevCodecModule.id)) return false
        return true
    }
}
