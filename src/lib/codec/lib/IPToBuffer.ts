import {Address6} from 'ip-address'
import {UInt32ToBuffer} from './NumberToBuffer'

/**
 * Convert IPv4 string to Buffer
 * @param ipv4
 * @constructor
 */
export function IPv4ToBuffer(ipv4: string): Buffer {
    const numArr: number[] = ipv4.split('.').map((value: string): number => parseInt(value)).map((value: number): number => value ? value : 0)
    return UInt32ToBuffer(parseInt(Buffer.from(numArr).toString('hex'), 16))
}

/**
 * Convert IPv6 string to Buffer
 * @param ipv6
 * @constructor
 */
export function IPv6ToBuffer(ipv6: string): Buffer {
    try {
        return Buffer.from(new Address6(ipv6).toByteArray())
    } catch (e) {
        return Buffer.alloc(16, 0)
    }
}
