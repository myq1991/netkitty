import {CodecDecodeResult} from '@netkitty/codec'
import {FrameRow} from './FrameRow'

/** A fully materialized frame: the lightweight row plus its decoded layers (fetched on demand via LRU). */
export type Frame = FrameRow & {
    capturedLength: number
    layers: CodecDecodeResult[]
}
