import {
    Float32ToBERHex,
    Int16ToBERHex,
    Int32ToBERHex,
    Int64ToBERHex,
    Int8ToBERHex,
    UInt16ToBERHex,
    UInt32ToBERHex,
    UInt64ToBERHex,
    UInt8ToBERHex
} from './NumberToBERHex'

/** Encode a signed 8-bit integer as a minimal-length BER INTEGER content buffer. */
export const Int8ToBERBuffer: (value: number) => Buffer = (value: number): Buffer => Buffer.from(Int8ToBERHex(value), 'hex')
/** Encode a signed 16-bit integer as a minimal-length BER INTEGER content buffer. */
export const Int16ToBERBuffer: (value: number) => Buffer = (value: number): Buffer => Buffer.from(Int16ToBERHex(value), 'hex')
/** Encode a signed 32-bit integer as a minimal-length BER INTEGER content buffer. */
export const Int32ToBERBuffer: (value: number) => Buffer = (value: number): Buffer => Buffer.from(Int32ToBERHex(value), 'hex')
/** Encode a signed 64-bit bigint as a minimal-length BER INTEGER content buffer. */
export const Int64ToBERBuffer: (value: bigint) => Buffer = (value: bigint): Buffer => Buffer.from(Int64ToBERHex(value), 'hex')
/** Encode an unsigned 8-bit integer as a BER INTEGER content buffer (00-padded to stay positive). */
export const UInt8ToBERBuffer: (value: number) => Buffer = (value: number): Buffer => Buffer.from(UInt8ToBERHex(value), 'hex')
/** Encode an unsigned 16-bit integer as a BER INTEGER content buffer (00-padded to stay positive). */
export const UInt16ToBERBuffer: (value: number) => Buffer = (value: number): Buffer => Buffer.from(UInt16ToBERHex(value), 'hex')
/** Encode an unsigned 32-bit integer as a BER INTEGER content buffer (00-padded to stay positive). */
export const UInt32ToBERBuffer: (value: number) => Buffer = (value: number): Buffer => Buffer.from(UInt32ToBERHex(value), 'hex')
/** Encode an unsigned 64-bit bigint as a BER INTEGER content buffer (00-padded to stay positive). */
export const UInt64ToBERBuffer: (value: bigint) => Buffer = (value: bigint): Buffer => Buffer.from(UInt64ToBERHex(value), 'hex')
/** Encode a 32-bit float as an IEC 61850 FLOATING-POINT content buffer (leading 08 exponent-width byte + IEEE-754 bytes). */
export const Float32ToBERBuffer: (value: number) => Buffer = (value: number): Buffer => Buffer.from(Float32ToBERHex(value), 'hex')
