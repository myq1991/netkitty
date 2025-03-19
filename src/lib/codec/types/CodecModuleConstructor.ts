import {BaseHeader} from '../lib/BaseHeader'

export type CodecModuleConstructor<T extends typeof BaseHeader = typeof BaseHeader> = T
