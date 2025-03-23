import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {UInt16ToHex} from '../lib/NumberToHex'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

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
                contentEncoding: StringContentEncodingEnum.UTF8,
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
                contentEncoding: StringContentEncodingEnum.UTF8,
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
                minLength: 4,
                maxLength: 4,
                label: 'EtherType',
                contentEncoding: StringContentEncodingEnum.HEX,
                decode: (): void => {
                    this.instance.etherType = this.readBytes(12, 2).toString('hex').padStart(4, '0')
                },
                encode: (): void => {
                    let etherType: string = this.instance.etherType ? UInt16ToHex(parseInt(this.instance.etherType.toString(), 16)) : UInt16ToHex(0x0000)
                    etherType = etherType ? etherType : UInt16ToHex(0x0000)
                    const typeBuffer: Buffer = Buffer.from(etherType, 'hex')
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
