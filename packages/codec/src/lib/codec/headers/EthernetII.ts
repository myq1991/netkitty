import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {UInt16ToHex} from '../../helper/NumberToHex'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

export class EthernetII extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    //Class-cached SCHEMA (④): field closures are plain functions taking dynamic `this` via .call(this),
    //so they capture no instance and the structure is built once and shared.
    public get SCHEMA(): ProtocolJSONSchema {
        return (EthernetII.#schemaCache ??= EthernetII.#buildSchema())
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
        type: 'object',
        properties: {
            dmac: {
                type: 'string',
                minLength: 17,
                maxLength: 17,
                label: 'Destination',
                contentEncoding: StringContentEncodingEnum.MAC,
                decode: function (this: EthernetII): void {
                    this.instance.dmac.setValue(Array.from(this.readBytes(0, 6)).map((value: number): string => value.toString(16).padStart(2, '0')).join(':'))
                },
                encode: function (this: EthernetII): void {
                    const dmac: number[] = this.instance.dmac
                        .getValue('00:00:00:00:00:00', (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                        .toString()
                        .split(':')
                        .map((value: string): number => parseInt(value, 16))
                        .map((value: number): number => value ? value : 0)
                    this.writeBytes(0, Buffer.alloc(6, Buffer.from(dmac)))
                }
            },
            smac: {
                type: 'string',
                minLength: 17,
                maxLength: 17,
                label: 'Source',
                contentEncoding: StringContentEncodingEnum.MAC,
                decode: function (this: EthernetII): void {
                    this.instance.smac.setValue(Array.from(this.readBytes(6, 6)).map((value: number): string => value.toString(16).padStart(2, '0')).join(':'))
                },
                encode: function (this: EthernetII): void {
                    const smac: number[] = this.instance.smac
                        .getValue('00:00:00:00:00:00', (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                        .toString()
                        .split(':')
                        .map((value: string): number => parseInt(value, 16))
                        .map((value: number): number => value ? value : 0)
                    this.writeBytes(6, Buffer.alloc(6, Buffer.from(smac)))
                }
            },
            etherType: {
                type: 'string',
                minLength: 4,
                maxLength: 4,
                label: 'EtherType',
                contentEncoding: StringContentEncodingEnum.HEX,
                decode: function (this: EthernetII): void {
                    this.instance.etherType.setValue(this.readBytes(12, 2).toString('hex').padStart(4, '0'))
                },
                encode: function (this: EthernetII): void {
                    const etherType: string = this.instance.etherType.getValue(UInt16ToHex(0x0000), (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                    const typeBuffer: Buffer = Buffer.from(etherType, 'hex')
                    if (typeBuffer.length < 2) typeBuffer.fill(0, 0, 1)
                    this.writeBytes(12, typeBuffer.subarray(0, 2))
                }
            }
        }
    }
    }

    public readonly id: string = 'eth'

    public readonly name: string = 'Ethernet II'

    public readonly nickname: string = 'ETH'

    public match(): boolean {
        const specialScenes: string[] = ['trill', 'vxlan', 'nvgre', 'mpls', 'qinq', 'gre', 'geneve']
        if (this.prevCodecModule && !specialScenes.includes(this.prevCodecModule.id)) return false
        return true
    }
}
