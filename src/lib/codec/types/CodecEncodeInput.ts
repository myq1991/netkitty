import {CodecDecodeResult} from './CodecDecodeResult'
import {CodecErrorInfo} from './CodecErrorInfo'

export type CodecEncodeInput = {
    name?: string
    nickname?: string
    protocol?: boolean
    errors?: CodecErrorInfo[]
} & CodecDecodeResult
