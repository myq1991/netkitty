export const Int8ToHex: (value: number) => string = (value: number): string => new Uint8Array(Int8Array.from([value]).buffer)[0].toString(16).padStart(2, '0')
export const Int16ToHex: (value: number) => string = (value: number): string => new Uint16Array(Int16Array.from([value]).buffer)[0].toString(16).padStart(4, '0')
export const Int32ToHex: (value: number) => string = (value: number): string => new Uint32Array(Int32Array.from([value]).buffer)[0].toString(16).padStart(8, '0')
export const Int64ToHex: (value: bigint) => string = (value: bigint): string => BigInt(value).toString(16).padStart(16, '0')
export const UInt8ToHex: (value: number) => string = (value: number): string => value.toString(16).padStart(2, '0')
export const UInt16ToHex: (value: number) => string = (value: number): string => value.toString(16).padStart(4, '0')
export const UInt32ToHex: (value: number) => string = (value: number): string => value.toString(16).padStart(8, '0')

export const Float32ToHex: (value: number) => string = (value: number): string => {
    const buffer = new ArrayBuffer(4)
    const dataView = new DataView(buffer)
    dataView.setFloat32(0, value, false)
    return dataView.getUint32(0, false).toString(16).padStart(8, '0')
}
