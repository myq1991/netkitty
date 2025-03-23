import {
    HexToFloat32,
    HexToInt16,
    HexToInt32,
    HexToInt64,
    HexToInt8,
    HexToUInt16,
    HexToUInt32,
    HexToUInt8
} from './HexToNumber'

export const BufferToInt8: (buffer: Buffer) => number = (buffer: Buffer): number => HexToInt8(buffer.toString('hex'))
export const BufferToInt16: (buffer: Buffer) => number = (buffer: Buffer): number => HexToInt16(buffer.toString('hex'))
export const BufferToInt32: (buffer: Buffer) => number = (buffer: Buffer): number => HexToInt32(buffer.toString('hex'))
export const BufferToInt64: (buffer: Buffer) => bigint = (buffer: Buffer): bigint => HexToInt64(buffer.toString('hex'))
export const BufferToUInt8: (buffer: Buffer) => number = (buffer: Buffer): number => HexToUInt8(buffer.toString('hex'))
export const BufferToUInt16: (buffer: Buffer) => number = (buffer: Buffer): number => HexToUInt16(buffer.toString('hex'))
export const BufferToUInt32: (buffer: Buffer) => number = (buffer: Buffer): number => HexToUInt32(buffer.toString('hex'))
export const BufferToFloat32: (buffer: Buffer) => number = (buffer: Buffer): number => HexToFloat32(buffer.toString('hex'))










