import {Address4, Address6} from 'ip-address'

/**
 * Convert Buffer to IPv4 string
 * @param buffer
 * @constructor
 */
export function BufferToIPv4(buffer: Buffer): string {
    return Address4.fromBigInt(BigInt(`0x${Buffer.concat([buffer.subarray(0, 4), Buffer.alloc(4)]).subarray(0, 4).toString('hex').padStart(8, '0')}`)).address
}

/**
 * Convert Buffer to IPv6 string
 * @param buffer
 * @constructor
 */
export function BufferToIPv6(buffer: Buffer): string {
    return Address6.fromBigInt(BigInt(`0x${Buffer.concat([buffer.subarray(0, 16), Buffer.alloc(16)]).subarray(0, 16).toString('hex').padStart(32, '0')}`)).address
}
