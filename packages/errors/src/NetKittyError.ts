/**
 * Base class for every error the netkitty packages throw. It extends the native `Error` and carries a
 * numeric `errno` plus a stable string `code` (so it is `NodeJS.ErrnoException`-compatible), and sets
 * `name` to the concrete subclass name. This lets a caller identify any netkitty error uniformly —
 * `catch (e) { if (e instanceof NetKittyError) ... }` — and branch on `code`/`errno`, regardless of which
 * package threw it.
 *
 * Concrete errors live in their own packages and extend this base (e.g. codec's CodecSchemaValidateError,
 * capture's DeviceNotFoundError), overriding `errno`/`code` — usually from the shared {@link ErrorCode}
 * registry. Pure JS, zero dependencies, browser-safe.
 */
export class NetKittyError extends Error implements NodeJS.ErrnoException {

    /** Numeric error number, grouped by package in the shared ErrorCode registry. Default 0 on the base. */
    public errno: number = 0

    /** Stable machine-readable error code, e.g. 'E_CODEC_SCHEMA_VALIDATE'. Default 'E_NETKITTY' on the base. */
    public code: string = 'E_NETKITTY'

    constructor(message?: string) {
        super(message)
        //name = the concrete subclass ('DeviceNotFoundError' etc.), so stack traces and logs read well.
        this.name = new.target.name
    }
}
