import {
    Int16ToBERHex,
    Int32ToBERHex,
    Int64ToBERHex,
    Int8ToBERHex,
    UInt16ToBERHex,
    UInt32ToBERHex,
    UInt8ToBERHex
} from './NumberToBERHex'

export const Int8ToBERBuffer: (value: number) => Buffer = (value: number): Buffer => Buffer.from(Int8ToBERHex(value), 'hex')
export const Int16ToBERBuffer: (value: number) => Buffer = (value: number): Buffer => Buffer.from(Int16ToBERHex(value), 'hex')
export const Int32ToBERBuffer: (value: number) => Buffer = (value: number): Buffer => Buffer.from(Int32ToBERHex(value), 'hex')
export const Int64ToBERBuffer: (value: bigint) => Buffer = (value: bigint): Buffer => Buffer.from(Int64ToBERHex(value), 'hex')
export const UInt8ToBERBuffer: (value: number) => Buffer = (value: number): Buffer => Buffer.from(UInt8ToBERHex(value), 'hex')
export const UInt16ToBERBuffer: (value: number) => Buffer = (value: number): Buffer => Buffer.from(UInt16ToBERHex(value), 'hex')
export const UInt32ToBERBuffer: (value: number) => Buffer = (value: number): Buffer => Buffer.from(UInt32ToBERHex(value), 'hex')
