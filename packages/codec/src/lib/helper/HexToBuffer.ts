/**
 * Convert hex to buffer
 * @param hex
 * @param bufferLength
 * @constructor
 */
export function HexToBuffer(hex: string, bufferLength?: number): Buffer {
    if (!hex) return Buffer.alloc(0)
    const inputHex: string = hex.length % 2 ? hex.padStart(hex.length + 1, '0') : hex
    const outputBufferLength: number = bufferLength ? bufferLength : inputHex.length / 2
    let buffer: Buffer = Buffer.from(inputHex, 'hex')
    if (buffer.length > outputBufferLength) {
        buffer.subarray(0, outputBufferLength)
    } else if (buffer.length < outputBufferLength) {
        const paddingLength: number = outputBufferLength - buffer.length
        buffer = Buffer.concat([
            Buffer.alloc(paddingLength, 0x00),
            buffer
        ])
    }
    return buffer
}
