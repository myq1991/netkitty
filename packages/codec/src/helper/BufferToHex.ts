/**
 * Convert a buffer to a lower-case hex string (two hex chars per byte, zero-padded).
 * @param buffer
 */
export function BufferToHex(buffer: Buffer): string {
    return buffer.toString('hex').padStart(buffer.length * 2, '0')
}
