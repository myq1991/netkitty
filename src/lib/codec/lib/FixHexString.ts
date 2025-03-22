/**
 * Fix Hex string length
 * @param rawHex
 * @constructor
 */
export function FixHexString(rawHex: string) {
    return rawHex.length % 2 ? `0${rawHex}` : rawHex
}
