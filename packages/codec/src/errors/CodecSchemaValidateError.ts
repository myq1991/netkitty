export class CodecSchemaValidateError extends Error implements NodeJS.ErrnoException {
    public errno: number = 2001
    public code: string = 'E_CODEC_SCHEMA_VALIDATE'
}
