import {CodecDecodeResult} from './CodecDecodeResult'

export type CodecEncodeInput = Pick<CodecDecodeResult, 'id' | 'data'> & Partial<Omit<CodecDecodeResult, 'id' | 'data'>>
