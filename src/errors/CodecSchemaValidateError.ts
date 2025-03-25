import {ErrorCode} from './common/ErrorCode'

export class CodecSchemaValidateError extends Error implements NodeJS.ErrnoException {
    public errno: number = ErrorCode.E_CODEC_SCHEMA_VALIDATE.errno
    public code: string = ErrorCode.E_CODEC_SCHEMA_VALIDATE.code
}
