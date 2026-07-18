import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'

export type CodecSchema = {
    readonly id: string
    readonly name: string
    readonly schema: ProtocolJSONSchema
}
