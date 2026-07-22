import {PostHandlerItem} from './PostHandlerItem'

export type CodecData = {
    packet: Buffer
    //Logical length of the packet, i.e. how many leading bytes of `packet` are real data. When absent
    //the physical buffer length IS the logical length (decode path: the buffer is never grown). Encode
    //grows `packet` with headroom (amortized doubling), so the physical buffer may be larger than this.
    packetLength?: number
    startPos: number
    postHandlers: PostHandlerItem[][]
}
