import {DecodeResult, EncodeResult, JSONSchemaProtocol} from '../../schema/JSONSchemaProtocol'
import {BaseProtocol} from '../lib/BaseProtocol'

export default class RawData extends BaseProtocol {

    public static get PROTOCOL_NAME(): string {
        return 'Raw Data'
    }

    public schema: JSONSchemaProtocol = {
        properties: {
            rawData: {
                type: 'string',
                encode: (input: string): EncodeResult => Buffer.from(input, 'hex'),
                decode: (data: Buffer): DecodeResult => {
                    return {
                        offset: 0,
                        length: data.length,
                        label: 'Data',
                        value: data.toString('hex')
                    }
                }
            }
        }
    }
}
