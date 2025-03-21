export const HexToInt8: (hex: string) => number = (hex: string): number => Int8Array.from([parseInt(hex, 16)])[0]
export const HexToInt16: (hex: string) => number = (hex: string): number => Int16Array.from([parseInt(hex, 16)])[0]
export const HexToInt32: (hex: string) => number = (hex: string): number => Int32Array.from([parseInt(hex, 16)])[0]
export const HexToInt64: (hex: string) => bigint = (hex: string): bigint => BigInt(`0x${hex}`)
export const HexToUInt8: (hex: string) => number = (hex: string): number => Uint8Array.from([parseInt(hex, 16)])[0]
export const HexToUInt16: (hex: string) => number = (hex: string): number => Uint16Array.from([parseInt(hex, 16)])[0]
export const HexToUInt32: (hex: string) => number = (hex: string): number => Uint32Array.from([parseInt(hex, 16)])[0]
export const HexToFloat32: (hex: string) => number = (hex: string): number => {
    const buffer = new ArrayBuffer(4)
    const dataView = new DataView(buffer)
    dataView.setUint32(0, parseInt(hex, 16), false)
    return dataView.getFloat32(0, false)
}
