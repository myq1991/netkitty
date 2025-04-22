import {Float32ToHex} from './NumberToHex'

function toBERHex(rawHex: string): string {
    const hex: string = rawHex.padStart(rawHex.length + rawHex.length % 2, '0')
    return Buffer.from(hex, 'hex')[0].toString(2).padStart(8, '0').startsWith('1') ? `00${hex}` : hex
}

export const Int8ToBERHex: (value: number) => string = (value: number): string => toBERHex(new Uint8Array(Int8Array.from([value]).buffer)[0].toString(16))
export const Int16ToBERHex: (value: number) => string = (value: number): string => toBERHex(new Uint16Array(Int16Array.from([value]).buffer)[0].toString(16))
export const Int32ToBERHex: (value: number) => string = (value: number): string => toBERHex(new Uint32Array(Int32Array.from([value]).buffer)[0].toString(16))
export const Int64ToBERHex: (value: bigint) => string = (value: bigint): string => toBERHex(BigInt(value).toString(16))
export const UInt8ToBERHex: (value: number) => string = (value: number): string => toBERHex(value.toString(16))
export const UInt16ToBERHex: (value: number) => string = (value: number): string => toBERHex(value.toString(16))
export const UInt32ToBERHex: (value: number) => string = (value: number): string => toBERHex(value.toString(16))
export const UInt64ToBERHex: (value: bigint) => string = (value: bigint): string => toBERHex(BigInt(value).toString(16))
//Float32 precision is always 8, therefore add '08' prefix for Float32ToHex result
export const Float32ToBERHex: (value: number) => string = (value: number): string => `08${Float32ToHex(value)}`