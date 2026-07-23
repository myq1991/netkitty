import {NetKittyError, ErrorCode} from '@netkitty/errors'

/** Thrown at the encode entry point when an input fails Ajv shape validation against the header schema. */
export class CodecSchemaValidateError extends NetKittyError {
    public errno: number = ErrorCode.E_CODEC_SCHEMA_VALIDATE.errno
    public code: string = ErrorCode.E_CODEC_SCHEMA_VALIDATE.code
}
