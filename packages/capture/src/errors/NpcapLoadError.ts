import {NetKittyError, ErrorCode} from '@netkitty/errors'

/** Thrown when the Npcap runtime fails to load (typically because Npcap is not installed on Windows). */
export class NpcapLoadError extends NetKittyError {
    public errno: number = ErrorCode.E_NPCAP_LOAD.errno
    public code: string = ErrorCode.E_NPCAP_LOAD.code
}
