import {Address6} from 'ip-address'

/**
 * Convert Buffer to IPv4 string
 * @param buffer
 * @constructor
 */
export function BufferToIPv4(buffer: Buffer): string {
    //Direct dotted-quad formatting; the old ip-address-library + BigInt + hex path micro-benchmarked
    //~20x slower per address. Missing bytes read as 0, matching the previous zero-padded behaviour.
    return `${buffer.length > 0 ? buffer[0] : 0}.${buffer.length > 1 ? buffer[1] : 0}.${buffer.length > 2 ? buffer[2] : 0}.${buffer.length > 3 ? buffer[3] : 0}`
}

/**
 * Convert Buffer to IPv6 string
 * @param buffer
 * @constructor
 */
export function BufferToIPv6(buffer: Buffer): string {
    return Address6.fromBigInt(BigInt(`0x${Buffer.concat([buffer.subarray(0, 16), Buffer.alloc(16)]).subarray(0, 16).toString('hex').padStart(32, '0')}`)).address
}
