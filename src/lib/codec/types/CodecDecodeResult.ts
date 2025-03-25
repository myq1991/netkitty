import {HeaderTreeNode} from './HeaderTreeNode'
import {CodecErrorInfo} from './CodecErrorInfo'

export type CodecDecodeResult = {
    id: string
    name: string
    nickname: string
    errors: CodecErrorInfo[]
    data: HeaderTreeNode
}
