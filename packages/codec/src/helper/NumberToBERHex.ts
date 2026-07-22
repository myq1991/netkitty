import {Float32ToHex} from './NumberToHex'

function toBERHex(rawHex: string): string {
    const hex: string = rawHex.padStart(rawHex.length + rawHex.length % 2, '0')
    return Buffer.from(hex, 'hex')[0].toString(2).padStart(8, '0').startsWith('1') ? `00${hex}` : hex
}

function toSignedBERHex(value: number | bigint): string {
    const v: bigint = BigInt(value)
    if (v >= 0n) {
        let hex: string = v.toString(16)
        if (hex.length % 2) hex = `0${hex}`
        if (parseInt(hex.slice(0, 2), 16) >= 0x80) hex = `00${hex}`
        return hex
    }
    let bytes: number = 1
    while (v < -(1n << (BigInt(bytes) * 8n - 1n))) bytes++
    const mask: bigint = (1n << (BigInt(bytes) * 8n)) - 1n
    return (v & mask).toString(16).padStart(bytes * 2, '0')
}

/** Encode a signed 8-bit integer as a minimal-length BER INTEGER content hex string (two's complement, leading sign byte as needed). */
export const Int8ToBERHex: (value: number) => string = (value: number): string => toSignedBERHex(value)
/** Encode a signed 16-bit integer as a minimal-length BER INTEGER content hex string (two's complement, leading sign byte as needed). */
export const Int16ToBERHex: (value: number) => string = (value: number): string => toSignedBERHex(value)
/** Encode a signed 32-bit integer as a minimal-length BER INTEGER content hex string (two's complement, leading sign byte as needed). */
export const Int32ToBERHex: (value: number) => string = (value: number): string => toSignedBERHex(value)
/** Encode a signed 64-bit bigint as a minimal-length BER INTEGER content hex string (two's complement, leading sign byte as needed). */
export const Int64ToBERHex: (value: bigint) => string = (value: bigint): string => toSignedBERHex(value)
/** Encode an unsigned 8-bit integer as a BER INTEGER content hex string (prepends a 00 byte when the high bit is set to keep it positive). */
export const UInt8ToBERHex: (value: number) => string = (value: number): string => toBERHex(value.toString(16))
/** Encode an unsigned 16-bit integer as a BER INTEGER content hex string (prepends a 00 byte when the high bit is set to keep it positive). */
export const UInt16ToBERHex: (value: number) => string = (value: number): string => toBERHex(value.toString(16))
/** Encode an unsigned 32-bit integer as a BER INTEGER content hex string (prepends a 00 byte when the high bit is set to keep it positive). */
export const UInt32ToBERHex: (value: number) => string = (value: number): string => toBERHex(value.toString(16))
/** Encode an unsigned 64-bit bigint as a BER INTEGER content hex string (prepends a 00 byte when the high bit is set to keep it positive). */
export const UInt64ToBERHex: (value: bigint) => string = (value: bigint): string => toBERHex(BigInt(value).toString(16))
//Float32 precision is always 8, therefore add '08' prefix for Float32ToHex result
/** Encode a 32-bit float as an IEC 61850 FLOATING-POINT content hex string (a leading 08 exponent-width byte followed by the big-endian IEEE-754 bytes). */
export const Float32ToBERHex: (value: number) => string = (value: number): string => `08${Float32ToHex(value)}`