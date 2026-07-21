/**
 *  Get BER encoded integer real length from buffer
 * @param buffer
 * @constructor
 */
export function GetBERIntegerLengthFromBuffer(buffer: Buffer): number {
    if (buffer[0] === 0) {
        return buffer.length - 1
    } else {
        return buffer.length
    }
}