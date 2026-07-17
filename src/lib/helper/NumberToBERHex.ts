import {Float32ToHex} from './NumberToHex'

function toBERHex(rawHex: string): string {
    const hex: string = rawHex.padStart(rawHex.length + rawHex.length % 2, '0')
    return Buffer.from(hex, 'hex')[0].toString(2).padStart(8, '0').startsWith('1') ? `00${hex}` : hex
}

function toSignedBERHex(value: number | bigint): string {
    let v: bigint = BigInt(value)
    if (v >= 0n) {
        let hex: string = v.toString(16)
        if (hex.length % 2) hex = `0${hex}`
        if (parseInt(hex.slice(0, 2), 16) >= 0x80) hex = `00${hex}`
        return hex
    }
    let bytes: number = 1
    while (v < -(1n << (BigInt(bytes) * 8n - 1n))) bytes++
    const mask: bigint = (1n << (BigInt(bytes) * 8n)) - 1n
    return (v & mask).toString(16).padStart(bytes * 2, "0")
}

export const Int8ToBERHex: (value: number) => string = (value: number): string => toSignedBERHex(value)
export const Int16ToBERHex: (value: number) => string = (value: number): string => toSignedBERHex(value)
export const Int32ToBERHex: (value: number) => string = (value: number): string => toSignedBERHex(value)
export const Int64ToBERHex: (value: bigint) => string = (value: bigint): string => toSignedBERHex(value)
export const UInt8ToBERHex: (value: number) => string = (value: number): string => toBERHex(value.toString(16))
export const UInt16ToBERHex: (value: number) => string = (value: number): string => toBERHex(value.toString(16))
export const UInt32ToBERHex: (value: number) => string = (value: number): string => toBERHex(value.toString(16))
export const UInt64ToBERHex: (value: bigint) => string = (value: bigint): string => toBERHex(BigInt(value).toString(16))
//Float32 precision is always 8, therefore add '08' prefix for Float32ToHex result
export const Float32ToBERHex: (value: number) => string = (value: number): string => `08${Float32ToHex(value)}`