export const HexToInt8: (hex: string) => number = (hex: string): number => Int8Array.from([parseInt(hex, 16)])[0]
export const HexToInt16: (hex: string) => number = (hex: string): number => Int16Array.from([parseInt(hex, 16)])[0]
export const HexToInt32: (hex: string) => number = (hex: string): number => Int32Array.from([parseInt(hex, 16)])[0]
export const HexToInt64: (hex: string) => bigint = (hex: string): bigint => {
    const INT64_MAX: bigint = BigInt('9223372036854775807')
    const INT64_MIN: bigint = BigInt('-9223372036854775808')
    const bigIntValue: bigint = BigInt(`0x${hex}`)
    if (bigIntValue < INT64_MIN || bigIntValue > INT64_MAX) return INT64_MAX
    return bigIntValue
}
export const HexToUInt8: (hex: string) => number = (hex: string): number => Uint8Array.from([parseInt(hex, 16)])[0]
export const HexToUInt16: (hex: string) => number = (hex: string): number => Uint16Array.from([parseInt(hex, 16)])[0]
export const HexToUInt32: (hex: string) => number = (hex: string): number => Uint32Array.from([parseInt(hex, 16)])[0]
export const HexToUInt64: (hex: string) => bigint = (hex: string): bigint => {
    const INT64_MAX: bigint = BigInt('18446744073709551615')
    const bigIntValue: bigint = BigInt(`0x${hex}`)
    if (bigIntValue < 0n || bigIntValue > INT64_MAX) return INT64_MAX
    return bigIntValue
}
export const HexToFloat32: (hex: string) => number = (hex: string): number => {
    const buffer = new ArrayBuffer(4)
    const dataView = new DataView(buffer)
    dataView.setUint32(0, parseInt(hex, 16), false)
    return dataView.getFloat32(0, false)
}
