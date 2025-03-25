import {CodecDecodeResult} from './CodecDecodeResult'
import {CodecErrorInfo} from './CodecErrorInfo'

export type CodecEncodeInput = {
    name?: string
    nickname?: string
    errors?: CodecErrorInfo[]
} & CodecDecodeResult
