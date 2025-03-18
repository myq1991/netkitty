import {DecodeResult, EncodeResult, JSONSchemaProtocol} from '../../schema/JSONSchemaProtocol'
import {BaseProtocol} from '../lib/BaseProtocol'

export default class Ethernet_II extends BaseProtocol {

    public static get PROTOCOL_NAME(): string {
        return 'Ethernet II'
    }

    public static get NEXT_HEADER_REF(): string {
        return 'etherType'
    }

    public schema: JSONSchemaProtocol = {
        $nextHeaderRef: Ethernet_II.NEXT_HEADER_REF,
        properties: {
            dmac: {
                type: 'string',
                maxLength: 17,
                minLength: 17,
                encode: (input: string): EncodeResult => Buffer.from(input.split(':').map(value => parseInt(value, 16))),
                decode: (data: Buffer): DecodeResult => ({
                    offset: 0,
                    length: 6,
                    label: 'Destination',
                    value: Array.from(data.subarray(0, 6)).map(value => value.toString(16).padStart(2, '0')).join(':')
                })
            },
            smac: {
                type: 'string',
                maxLength: 17,
                minLength: 17,
                encode: (input: string): EncodeResult => Buffer.from(input.split(':').map(value => parseInt(value, 16))),
                decode: (data: Buffer): DecodeResult => ({
                    offset: 6,
                    length: 6,
                    label: 'Source',
                    value: Array.from(data.subarray(6, 12)).map(value => value.toString(16).padStart(2, '0')).join(':')
                })
            },
            etherType: {
                type: 'number',
                encode: (input: number): EncodeResult => Buffer.from(input.toString(16).padStart(4, '0'), 'hex'),
                decode: (data: Buffer): DecodeResult => {
                    const value: number = parseInt(data.subarray(12, 14).toString('hex'), 16)
                    return {
                        offset: 12,
                        length: 2,
                        label: value < 0x0600 ? 'Length' : 'Type',
                        value: value
                    }
                }
            }
        }
    }
}
