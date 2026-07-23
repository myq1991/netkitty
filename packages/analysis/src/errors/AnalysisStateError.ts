import {NetKittyError, ErrorCode} from '@netkitty/errors'

/** Thrown when an Analysis method is used before a source is open — call open() or watch() first. */
export class AnalysisStateError extends NetKittyError {
    public errno: number = ErrorCode.E_ANALYSIS_STATE.errno
    public code: string = ErrorCode.E_ANALYSIS_STATE.code
}
