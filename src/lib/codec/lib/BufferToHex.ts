export function BufferToHex(buffer: Buffer): string {
    return buffer.toString('hex').padStart(buffer.length * 2, '0')
}
