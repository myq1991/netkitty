import {
    Float32ToHex,
    Int16ToHex,
    Int32ToHex,
    Int64ToHex,
    Int8ToHex,
    UInt16ToHex,
    UInt32ToHex,
    UInt8ToHex
} from './NumberToHex'

export const Int8ToBuffer: (value: number) => Buffer = (value: number): Buffer => Buffer.from(Int8ToHex(value), 'hex')
export const Int16ToBuffer: (value: number) => Buffer = (value: number): Buffer => Buffer.from(Int16ToHex(value), 'hex')
export const Int32ToBuffer: (value: number) => Buffer = (value: number): Buffer => Buffer.from(Int32ToHex(value), 'hex')
export const Int64ToBuffer: (value: bigint) => Buffer = (value: bigint): Buffer => Buffer.from(Int64ToHex(value), 'hex')
export const UInt8ToBuffer: (value: number) => Buffer = (value: number): Buffer => Buffer.from(UInt8ToHex(value), 'hex')
export const UInt16ToBuffer: (value: number) => Buffer = (value: number): Buffer => Buffer.from(UInt16ToHex(value), 'hex')
export const UInt32ToBuffer: (value: number) => Buffer = (value: number): Buffer => Buffer.from(UInt32ToHex(value), 'hex')
export const Float32ToBuffer: (value: number) => Buffer = (value: number): Buffer => Buffer.from(Float32ToHex(value), 'hex')
