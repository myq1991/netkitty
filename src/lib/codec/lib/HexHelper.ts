export const HexToInt8: (hex: string) => number = (hex: string): number => Int8Array.from([parseInt(hex)])[0]
export const Int8ToHex: (value: number) => string = (value: number): string => new Uint8Array(Int8Array.from([value]).buffer)[0].toString(16).padStart(2, '0')
export const HexToInt16: (hex: string) => number = (hex: string): number => Int16Array.from([parseInt(hex)])[0]
export const Int16ToHex: (value: number) => string = (value: number): string => new Uint16Array(Int16Array.from([value]).buffer)[0].toString(16).padStart(4, '0')
export const HexToInt32: (hex: string) => number = (hex: string): number => Int32Array.from([parseInt(hex)])[0]
export const Int32ToHex: (value: number) => string = (value: number): string => new Uint32Array(Int32Array.from([value]).buffer)[0].toString(16).padStart(8, '0')
export const HexToInt64: (hex: string) => number = (hex: string): number => parseInt(BigInt64Array.from([parseInt(hex)])[0].toString())
export const Int64ToHex: (value: number) => string = (value: number): string => BigInt(value).toString(16).padStart(16, '0')
export const HexToUInt8: (hex: string) => number = (hex: string): number => Uint8Array.from([parseInt(hex)])[0]
export const UInt8ToHex: (value: number) => string = (value: number): string => value.toString(16).padStart(2, '0')
export const HexToUInt16: (hex: string) => number = (hex: string): number => Uint16Array.from([parseInt(hex)])[0]
export const UInt16ToHex: (value: number) => string = (value: number): string => value.toString(16).padStart(4, '0')
export const HexToUInt32: (hex: string) => number = (hex: string): number => Uint32Array.from([parseInt(hex)])[0]
export const UInt32ToHex: (value: number) => string = (value: number): string => value.toString(16).padStart(8, '0')
export const HexToFloat32: (hex: string) => number = (hex: string): number => {
    const buffer = new ArrayBuffer(4)
    const dataView = new DataView(buffer)
    dataView.setUint32(0, parseInt(hex, 16), false)
    return dataView.getFloat32(0, false)
}
export const Float32ToHex: (value: number) => string = (value: number): string => {
    const buffer = new ArrayBuffer(4)
    const dataView = new DataView(buffer)
    dataView.setFloat32(0, value, false)
    return dataView.getUint32(0, false).toString(16).padStart(8, '0')
}
