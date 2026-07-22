/** Parse a hex string as a signed 8-bit integer (two's complement). */
export const HexToInt8: (hex: string) => number = (hex: string): number => Int8Array.from([parseInt(hex, 16)])[0]
/** Parse a big-endian hex string as a signed 16-bit integer (two's complement). */
export const HexToInt16: (hex: string) => number = (hex: string): number => Int16Array.from([parseInt(hex, 16)])[0]
/** Parse a big-endian hex string as a signed 32-bit integer (two's complement). */
export const HexToInt32: (hex: string) => number = (hex: string): number => Int32Array.from([parseInt(hex, 16)])[0]
/** Parse a big-endian hex string as a signed 64-bit bigint (clamped to the int64 range on overflow). */
export const HexToInt64: (hex: string) => bigint = (hex: string): bigint => {
    const INT64_MAX: bigint = BigInt('9223372036854775807')
    const INT64_MIN: bigint = BigInt('-9223372036854775808')
    const bigIntValue: bigint = BigInt(`0x${hex}`)
    if (bigIntValue < INT64_MIN || bigIntValue > INT64_MAX) return INT64_MAX
    return bigIntValue
}
/** Parse a hex string as an unsigned 8-bit integer. */
export const HexToUInt8: (hex: string) => number = (hex: string): number => Uint8Array.from([parseInt(hex, 16)])[0]
/** Parse a big-endian hex string as an unsigned 16-bit integer. */
export const HexToUInt16: (hex: string) => number = (hex: string): number => Uint16Array.from([parseInt(hex, 16)])[0]
/** Parse a big-endian hex string as an unsigned 32-bit integer. */
export const HexToUInt32: (hex: string) => number = (hex: string): number => Uint32Array.from([parseInt(hex, 16)])[0]
/** Parse a big-endian hex string as an unsigned 64-bit bigint (clamped to the uint64 range on overflow). */
export const HexToUInt64: (hex: string) => bigint = (hex: string): bigint => {
    const INT64_MAX: bigint = BigInt('18446744073709551615')
    const bigIntValue: bigint = BigInt(`0x${hex}`)
    if (bigIntValue < 0n || bigIntValue > INT64_MAX) return INT64_MAX
    return bigIntValue
}
/** Parse a big-endian hex string as an IEEE-754 32-bit float. */
export const HexToFloat32: (hex: string) => number = (hex: string): number => {
    const buffer: ArrayBuffer = new ArrayBuffer(4)
    const dataView: DataView = new DataView(buffer)
    dataView.setUint32(0, parseInt(hex, 16), false)
    return dataView.getFloat32(0, false)
}
