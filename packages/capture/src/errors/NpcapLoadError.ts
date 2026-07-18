import {ErrorCode} from './common/ErrorCode'

export class NpcapLoadError extends Error implements NodeJS.ErrnoException {
    public errno: number = ErrorCode.E_NPCAP_LOAD.errno
    public code: string = ErrorCode.E_NPCAP_LOAD.code
}
