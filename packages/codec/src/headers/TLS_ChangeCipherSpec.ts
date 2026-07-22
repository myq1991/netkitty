import {ProtocolJSONSchema} from '../schema/ProtocolJSONSchema'
import {BaseHeader} from '../abstracts/BaseHeader'
import {BufferToInt8, BufferToUInt16} from '../helper/BufferToNumber'
import {BufferToHex} from '../helper/BufferToHex'
import {UInt16ToBuffer, UInt8ToBuffer} from '../helper/NumberToBuffer'
import {HexToBuffer} from '../helper/HexToBuffer'

enum TLSver {
    SSL_3_0 = 'SSL3.0',
    TLS_1_0 = 'TLS1.0',
    TLS_1_1 = 'TLS1.1',
    TLS_1_2 = 'TLS1.2',
    TLS_1_3 = 'TLS1.3',
}

/**
 * TLS ChangeCipherSpec protocol — a TLS/SSL record signaling the switch to the negotiated cipher, over TCP
 * (heuristically, port 443). This codec decodes the 5-octet TLS record header plus its body: an 8-bit
 * Content Type (`contentType`, offset 0, = 20 / 0x14 for ChangeCipherSpec), a 16-bit legacy Version
 * (`version`, offset 1, mapped to the labels SSL3.0 / TLS1.0 / TLS1.1 / TLS1.2 / TLS1.3 for 0x0300-0x0304,
 * else "0"), a 16-bit record Length (`length`, offset 3), and the message body
 * (`change_cipher_spec_message`, offset 5, `length` octets — canonically the single byte 0x01).
 *
 * The body is kept verbatim as hex (byte-perfect) and the Length is honored as given, so a well-formed
 * record round-trips byte-for-byte. In the heuristic chain (`heuristicFallback`), match() requires a
 * Content Type of 0x14 and a recognized legacy Version (0x0300-0x0304).
 */
export class TLS_ChangeCipherSpec extends BaseHeader {
    public SCHEMA: ProtocolJSONSchema = {
        type: 'object',
        properties: {
            contentType: {
                type: 'integer',
                label: 'Content Type',
                minimum: 0,
                maximum: 255,
                decode: (): void => {
                    this.instance.contentType.setValue(BufferToInt8(this.readBytes(0, 1)))

                },
                encode: (): void => {

                    const contentType: Buffer = UInt8ToBuffer(this.instance.contentType.getValue(0, (nodePath: string): void => this.recordError(nodePath, 'Not found')))
                    this.writeBytes(0, contentType)

                }
            },
            version: {
                type: 'string',
                label: 'Legacy Version',
                minimum: 0,
                maximum: 65535,
                decode: (): void => {
                    const version: number = BufferToUInt16(this.readBytes(1, 2))
                    switch (version) {
                        case 768: {
                            this.instance.version.setValue(TLSver.SSL_3_0)
                        }
                            break
                        case 769: {
                            this.instance.version.setValue(TLSver.TLS_1_0)
                        }
                            break
                        case 770: {
                            this.instance.version.setValue(TLSver.TLS_1_1)
                        }
                            break
                        case 771: {
                            this.instance.version.setValue(TLSver.TLS_1_2)
                        }
                            break
                        case 772: {
                            this.instance.version.setValue(TLSver.TLS_1_3)
                        }
                            break
                        default: {
                            this.instance.version.setValue('0')
                        }
                    }


                },
                encode: (): void => {
                    const version: string = this.instance.version.getValue('0', (nodePath: string): void => this.recordError(nodePath, 'Not found'))
                    switch (version) {
                        case TLSver.SSL_3_0: {
                            const version: Buffer = UInt16ToBuffer(768)
                            this.writeBytes(1, version)
                        }
                            break
                        case TLSver.TLS_1_0: {
                            const version: Buffer = UInt16ToBuffer(769)
                            this.writeBytes(1, version)
                        }
                            break
                        case TLSver.TLS_1_1: {
                            const version: Buffer = UInt16ToBuffer(770)
                            this.writeBytes(1, version)
                        }
                            break
                        case TLSver.TLS_1_2: {
                            const version: Buffer = UInt16ToBuffer(771)
                            this.writeBytes(1, version)
                        }
                            break
                        case TLSver.TLS_1_3: {
                            const version: Buffer = UInt16ToBuffer(772)
                            this.writeBytes(1, version)
                        }
                            break
                        default: {
                            this.writeBytes(1, UInt16ToBuffer(0))
                        }
                    }
                }
            },
            length: {
                type: 'integer',
                label: 'Length',
                minimum: 0,
                maximum: 65535,
                decode: (): void => {
                    this.instance.length.setValue(BufferToUInt16(this.readBytes(3, 2)))
                },
                encode: (): void => {
                    const length: Buffer = UInt16ToBuffer(this.instance.length.getValue(0, (nodePath: string): void => this.recordError(nodePath, 'Not found')))
                    this.writeBytes(3, length)
                }
            },
            change_cipher_spec_message: {
                type: 'string',
                label: 'Change Cipher Spec Message',
                decode: (): void => {
                    const length: number = this.instance.length.getValue(0, (nodePath: string): void => this.recordError(nodePath, 'Not found'))
                    this.instance.change_cipher_spec_message.setValue(BufferToHex(this.readBytes(5, length)))
                },
                encode: (): void => {
                    const message: Buffer = HexToBuffer(this.instance.change_cipher_spec_message.getValue('0', (nodePath: string): void => this.recordError(nodePath, 'Not found')))
                    this.writeBytes(5, message)
                }
            }


        }
    }
    public id: string = 'tls-ccsp'
    public readonly matchKeys: string[] = ['tcpport:443']
    public readonly heuristicFallback: boolean = true
    public name: string = 'Transport Layer Security(ChangeCipherSpec Protocol)'
    public nickname: string = 'TLS-ChangeCipherSpec'

    public match(): boolean {
        if (!this.prevCodecModule) return false
        if (BufferToHex(this.readBytes(0, 1)) != '14') return false
        const version: number = BufferToUInt16(this.readBytes(1, 2))
        const validVersions: number[] = [768, 769, 770, 771, 772]
        return validVersions.includes(version)
    }

}