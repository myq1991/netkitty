import {HeaderTreeNode} from './HeaderTreeNode'
import {CodecErrorInfo} from './CodecErrorInfo'

export type CodecDecodeResult = {
    id: string
    name: string
    nickname: string
    protocol: boolean
    errors: CodecErrorInfo[]
    data: HeaderTreeNode
}
