/** Convert a signed 8-bit integer to a 2-char two's-complement hex string. */
export const Int8ToHex: (value: number) => string = (value: number): string => new Uint8Array(Int8Array.from([value]).buffer)[0].toString(16).padStart(2, '0')
/** Convert a signed 16-bit integer to a 4-char big-endian two's-complement hex string. */
export const Int16ToHex: (value: number) => string = (value: number): string => new Uint16Array(Int16Array.from([value]).buffer)[0].toString(16).padStart(4, '0')
/** Convert a signed 32-bit integer to an 8-char big-endian two's-complement hex string. */
export const Int32ToHex: (value: number) => string = (value: number): string => new Uint32Array(Int32Array.from([value]).buffer)[0].toString(16).padStart(8, '0')
/** Convert a signed 64-bit bigint to a 16-char big-endian hex string. */
export const Int64ToHex: (value: bigint) => string = (value: bigint): string => BigInt(value).toString(16).padStart(16, '0')
/** Convert an unsigned 8-bit integer to a 2-char hex string. */
export const UInt8ToHex: (value: number) => string = (value: number): string => value.toString(16).padStart(2, '0')
/** Convert an unsigned 16-bit integer to a 4-char big-endian hex string. */
export const UInt16ToHex: (value: number) => string = (value: number): string => value.toString(16).padStart(4, '0')
/** Convert an unsigned 32-bit integer to an 8-char big-endian hex string. */
export const UInt32ToHex: (value: number) => string = (value: number): string => value.toString(16).padStart(8, '0')
/** Convert an unsigned 64-bit bigint to a 16-char big-endian hex string. */
export const UInt64ToHex: (value: bigint) => string = (value: bigint): string => BigInt(value).toString(16).padStart(16, '0')

/** Convert an IEEE-754 32-bit float to an 8-char big-endian hex string. */
export const Float32ToHex: (value: number) => string = (value: number): string => {
    const buffer: ArrayBuffer = new ArrayBuffer(4)
    const dataView: DataView = new DataView(buffer)
    dataView.setFloat32(0, value, false)
    return dataView.getUint32(0, false).toString(16).padStart(8, '0')
}
