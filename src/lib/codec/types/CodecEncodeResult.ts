import {CodecErrorInfo} from './CodecErrorInfo'

export type CodecEncodeResult = {
    packet: Buffer
    errors: CodecErrorInfo[]
}
