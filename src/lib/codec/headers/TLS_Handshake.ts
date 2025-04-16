import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {BaseHeader} from '../abstracts/BaseHeader'
import {
    BufferToInt8,
    BufferToUInt16,
    BufferToUInt32,
    BufferToUInt8
} from '../../helper/BufferToNumber'
import {BufferToHex} from '../../helper/BufferToHex'
import {UInt16ToBuffer, UInt8ToBuffer} from '../../helper/NumberToBuffer'
import {HexToBuffer} from '../../helper/HexToBuffer'

enum TLSver {
    SSL_3_0 = 'SSL3.0',
    TLS_1_0 = 'TLS1.0',
    TLS_1_1 = 'TLS1.1',
    TLS_1_2 = 'TLS1.2',
    TLS_1_3 = 'TLS1.3',
}

enum HandshakeType {
    Handshake_1 = 'HelloRequest',
    Handshake_2 = 'ClientHello',
    Handshake_3 = 'ServerHello',
    Handshake_4 = 'NewSessionTicket',
    Handshake_5 = 'EncryptedExtensions',
    Handshake_6 = 'Certificate',
    Handshake_7 = 'ServerKeyExchange',
    Handshake_8 = 'CertificateRequest',
    Handshake_9 = 'ServerHelloDone',
    Handshake_10 = 'CertificateVerify',
    Handshake_11 = 'ClientKeyExchange',
    Handshake_12 = 'Finished',
}

export class TLS_Handshake extends BaseHeader {
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
            handshakeType: {
                type: 'string',
                label: 'Handshake Type',
                minimum: 0,
                maximum: 65535,
                decode: (): void => {
                    const handshakeType: number = BufferToUInt8(this.readBytes(5, 1))
                    switch (handshakeType) {
                        case 0: {
                            this.instance.handshakeType.setValue(HandshakeType.Handshake_1)
                        }
                            break
                        case 1: {
                            this.instance.handshakeType.setValue(HandshakeType.Handshake_2)
                        }
                            break
                        case 2: {
                            this.instance.handshakeType.setValue(HandshakeType.Handshake_3)
                        }
                            break
                        case 4: {
                            this.instance.handshakeType.setValue(HandshakeType.Handshake_4)
                        }
                            break
                        case 8: {
                            this.instance.handshakeType.setValue(HandshakeType.Handshake_5)
                        }
                            break
                        case 11: {
                            this.instance.handshakeType.setValue(HandshakeType.Handshake_6)
                        }
                            break
                        case 12: {
                            this.instance.handshakeType.setValue(HandshakeType.Handshake_7)
                        }
                            break
                        case 13: {
                            this.instance.handshakeType.setValue(HandshakeType.Handshake_8)
                        }
                            break
                        case 14: {
                            this.instance.handshakeType.setValue(HandshakeType.Handshake_9)
                        }
                            break
                        case 15: {
                            this.instance.handshakeType.setValue(HandshakeType.Handshake_10)
                        }
                            break
                        case 16: {
                            this.instance.handshakeType.setValue(HandshakeType.Handshake_11)
                        }
                            break
                        case 20: {
                            this.instance.handshakeType.setValue(HandshakeType.Handshake_12)
                        }
                            break
                        default: {
                            this.instance.handshakeType.setValue(BufferToUInt8(this.readBytes(5, 1)))
                        }
                    }
                },
                encode: (): void => {
                    const handshakeType: string = this.instance.handshakeType.getValue('0')
                    switch (handshakeType) {
                        case HandshakeType.Handshake_1: {
                            const handshakeType: Buffer = UInt8ToBuffer(0)
                            this.writeBytes(5, handshakeType)
                        }
                            break
                        case HandshakeType.Handshake_2: {
                            const handshakeType: Buffer = UInt8ToBuffer(1)
                            this.writeBytes(5, handshakeType)
                        }
                            break
                        case HandshakeType.Handshake_3: {
                            const handshakeType: Buffer = UInt8ToBuffer(2)
                            this.writeBytes(5, handshakeType)
                        }
                            break
                        case HandshakeType.Handshake_4: {
                            const handshakeType: Buffer = UInt8ToBuffer(4)
                            this.writeBytes(5, handshakeType)
                        }
                            break
                        case HandshakeType.Handshake_5: {
                            const handshakeType: Buffer = UInt8ToBuffer(8)
                            this.writeBytes(5, handshakeType)
                        }
                            break
                        case HandshakeType.Handshake_6: {
                            const handshakeType: Buffer = UInt8ToBuffer(11)
                            this.writeBytes(5, handshakeType)
                        }
                            break
                        case HandshakeType.Handshake_7: {
                            const handshakeType: Buffer = UInt8ToBuffer(12)
                            this.writeBytes(5, handshakeType)
                        }
                            break
                        case HandshakeType.Handshake_8: {
                            const handshakeType: Buffer = UInt8ToBuffer(13)
                            this.writeBytes(5, handshakeType)
                        }
                            break
                        case HandshakeType.Handshake_9: {
                            const handshakeType: Buffer = UInt8ToBuffer(14)
                            this.writeBytes(5, handshakeType)
                        }
                            break
                        case HandshakeType.Handshake_10: {
                            const handshakeType: Buffer = UInt8ToBuffer(15)
                            this.writeBytes(5, handshakeType)
                        }
                            break
                        case HandshakeType.Handshake_11: {
                            const handshakeType: Buffer = UInt8ToBuffer(16)
                            this.writeBytes(5, handshakeType)
                        }
                            break
                        case HandshakeType.Handshake_12: {
                            const handshakeType: Buffer = UInt8ToBuffer(20)
                            this.writeBytes(5, handshakeType)
                        }
                            break
                        default: {
                            const handshakeType1: number = parseInt(handshakeType)
                            this.writeBytes(5, UInt8ToBuffer(handshakeType1))
                        }

                    }
                }
            },
            handshakeLength: {
                type: 'integer',
                label: 'Length',
                minimum: 0,
                maximum: 1118481,
                decode: (): void => {
                    this.instance.handshakeLength.setValue(BufferToUInt32(this.readBytes(6, 3)))
                },
                encode: (): void => {
                    const length1: number = (this.instance.handshakeLength.getValue(0, (nodePath: string): void => this.recordError(nodePath, 'Not found')))
                    const length2: string = length1.toString(16).padStart(6, '0')
                    const length3: Buffer = HexToBuffer(length2)
                    this.writeBytes(6, length3)
                }
            },
            messagedata: {
                type: 'string',
                label: 'Messagedata',
                decode: (): void => {
                    const length: number = (this.instance.handshakeLength.getValue(0, (nodePath: string): void => this.recordError(nodePath, 'Not found')))
                    this.instance.messagedata.setValue(BufferToHex(this.readBytes(9, length)))
                },
                encode: (): void => {
                    const message: Buffer = HexToBuffer(this.instance.messagedata.getValue('0', (nodePath: string): void => this.recordError(nodePath, 'Not found')))
                    this.writeBytes(9, message)
                }
            }


        }
    }
    public id: string = 'tls-handshake'
    public name: string = 'Transport Layer Security(Handshake Protocol)'
    public nickname: string = 'TLS'

    public match(): boolean {
        if (!this.prevCodecModule) return false
        if (BufferToHex(this.readBytes(0, 1)) != '16') return false
        const version: number = BufferToUInt16(this.readBytes(1, 2))
        const validVersions: number[] = [768, 769, 770, 771, 772]
        return validVersions.includes(version)
    }

}