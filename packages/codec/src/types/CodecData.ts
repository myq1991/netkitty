import {PostHandlerItem} from './PostHandlerItem'

export type CodecData = {
    packet: Buffer
    startPos: number
    postHandlers: PostHandlerItem[][]
}
