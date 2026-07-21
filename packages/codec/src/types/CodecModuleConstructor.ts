import {BaseHeader} from '../abstracts/BaseHeader'

export type CodecModuleConstructor<T extends typeof BaseHeader = typeof BaseHeader> = T
