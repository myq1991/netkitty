import {ErrorCode} from './common/ErrorCode'

/** Thrown when the Npcap runtime fails to load (typically because Npcap is not installed on Windows). */
export class NpcapLoadError extends Error implements NodeJS.ErrnoException {
    public errno: number = ErrorCode.E_NPCAP_LOAD.errno
    public code: string = ErrorCode.E_NPCAP_LOAD.code
}
