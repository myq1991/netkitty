import {DecodeResult, EncodeResult, JSONSchemaProtocol} from '../../schema/JSONSchemaProtocol'
import {BaseProtocol} from '../lib/BaseProtocol'

export default class VirtualLAN802dot1Q extends BaseProtocol {

    public static get PROTOCOL_NAME(): string {
        return '802.1Q Virtual LAN'
    }

    public static get ID(): number {
        return 0x8100
    }

    public static get PREV_HEADER_REF(): string {
        return 'etherType'
    }

    public static get NEXT_HEADER_REF(): string {
        return 'etherType'
    }

    public schema: JSONSchemaProtocol = {
        $headerId: VirtualLAN802dot1Q.ID,
        $prevHeaderRef: VirtualLAN802dot1Q.PREV_HEADER_REF,
        $nextHeaderRef: VirtualLAN802dot1Q.NEXT_HEADER_REF,
        properties: {
            // priority: {},
            // DEI: {},
            // id: {},
            etherType: {
                type: 'number',
                encode: (input: number): EncodeResult => Buffer.from(input.toString(16).padStart(4, '0'), 'hex'),
                decode: (data: Buffer): DecodeResult => ({
                    offset: 12,
                    length: 2,
                    label: 'Type',
                    value: parseInt(data.subarray(2, 4).toString('hex'), 16)
                })
            }
        }
    }
}
