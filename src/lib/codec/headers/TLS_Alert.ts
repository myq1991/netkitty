import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {BaseHeader} from '../abstracts/BaseHeader'
import {BufferToInt8, BufferToUInt16, BufferToUInt8} from '../../helper/BufferToNumber'
import {UInt16ToBuffer, UInt8ToBuffer} from '../../helper/NumberToBuffer'

enum TLSver {
    SSL_3_0 = 'SSL3.0',
    TLS_1_0 = 'TLS1.0',
    TLS_1_1 = 'TLS1.1',
    TLS_1_2 = 'TLS1.2',
    TLS_1_3 = 'TLS1.3',
}

enum Description_type {
    code_0 = 'Close notify',
    code_10 = 'Unexpected message',
    code_20 = 'Bad record MAC',
    code_21 = 'Decryption failed',
    code_22 = 'Record overflow',
    code_30 = 'Decompression failure',
    code_40 = 'Handshake failure',
    code_41 = 'No certificate',
    code_42 = 'Bad certificate',
    code_43 = 'Unsupported certificate',
    code_44 = 'Certificate revoked',
    code_45 = 'Certificate expired',
    code_46 = 'Certificate unknown',
    code_47 = 'Illegal parameter',
    code_48 = 'Unknown CA (Certificate authority)',
    code_49 = 'Access denied',
    code_50 = 'Decode error',
    code_51 = 'Decrypt error',
    code_60 = 'Export restriction',
    code_70 = 'Protocol version',
    code_71 = 'Insufficient security',
    code_80 = 'Internal error',
    code_86 = 'Inappropriate fallback',
    code_90 = 'User canceled',
    code_100 = 'No renegotiation',
    code_110 = 'Unsupported extension',
    code_111 = 'Certificate unobtainable',
    code_112 = 'Unrecognized name',
    code_113 = 'Bad certificate status response',
    code_114 = 'Bad certificate hash value	 ',
    code_115 = 'Unknown PSK identity (used in TLS-PSK and TLS-SRP)',
    code_116 = 'Certificate required',
    code_120 = 'No application protocol',
    code_255 = 'No application protocol',
}

export class TLS_Alert extends BaseHeader {
    public SCHEMA: ProtocolJSONSchema = {
        type: 'object',
        properties: {
            contentType: {
                type: 'integer',
                label: 'Content Type',
                minimum: 0,
                maximum: 65535,
                decode: (): void => {
                    this.instance.contentType.setValue(BufferToUInt8(this.readBytes(0, 1)))
                },
                encode: (): void => {
                    const contentTyppe: number = this.instance.contentType.getValue(0, (nodePath: string): void => this.recordError(nodePath, 'Not found'))
                    this.writeBytes(0, UInt8ToBuffer(contentTyppe))
                }
            },
            version: {
                type: 'string',
                label: 'Legacy Version',
                minimum: 0,
                maximum: 65535,
                decode: (): void => {
                    this.instance.version.setValue(BufferToUInt16(this.readBytes(1, 2)))
                    const version: number = this.instance.version.getValue(0, (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
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
                label: 'Legacy Version',
                minimum: 0,
                maximum: 255,
                decode: (): void => {
                    this.instance.length.setValue(BufferToUInt16(this.readBytes(3, 2)))
                },
                encode: (): void => {
                    const length: Buffer = UInt16ToBuffer(this.instance.length.getValue(0, (nodePath: string): void => this.recordError(nodePath, 'Not found')))
                    this.writeBytes(3, length)

                }
            },
            levelType: {
                type: 'string',
                label: 'Alert Level Type ',
                minimum: 0,
                maximum: 255,
                decode: (): void => {
                    this.instance.levelType.setValue(BufferToUInt8(this.readBytes(5, 1)))
                    const type: number = this.instance.levelType.getValue(0, (nodePath: string): void => this.recordError(nodePath, 'Not found'))
                    switch (type) {
                        case 1: {
                            this.instance.levelType.setValue('Warning')
                        }
                            break
                        case 2: {
                            this.instance.levelType.setValue('Fatal')
                        }
                            break
                        default: {
                            this.instance.levelType.setValue(BufferToUInt8(this.readBytes(5, 1)))
                        }
                    }
                },
                encode: (): void => {
                    const type: string = this.instance.levelType.getValue('0', (nodePath: string): void => this.recordError(nodePath, 'Not found'))
                    switch (type) {
                        case 'Warning': {
                            const type: Buffer = UInt8ToBuffer(1)
                            this.writeBytes(5, type)
                        }
                            break
                        case 'Fatal': {
                            const type: Buffer = UInt8ToBuffer(2)
                            this.writeBytes(5, type)
                        }
                            break
                        default: {
                            const type1: number = parseInt(type, 10)
                            this.writeBytes(5, UInt8ToBuffer(type1))
                        }
                    }
                }
            },
            descriptionType: {
                type: 'string',
                label: 'Alert Description Types',
                minimum: 0,
                maximum: 255,
                decode: (): void => {
                    this.instance.descriptionType.setValue(BufferToUInt8(this.readBytes(6, 1)))
                    const type: number = this.instance.descriptionType.getValue(0, (nodePath: string): void => this.recordError(nodePath, 'Not found'))
                    switch (type) {
                        case 0: {
                            this.instance.descriptionType.setValue(Description_type.code_0)
                        }
                            break
                        case 10: {
                            this.instance.descriptionType.setValue(Description_type.code_10)
                        }
                            break
                        case 20: {
                            this.instance.descriptionType.setValue(Description_type.code_20)
                        }
                            break
                        case 21: {
                            this.instance.descriptionType.setValue(Description_type.code_21)
                        }
                            break
                        case 22: {
                            this.instance.descriptionType.setValue(Description_type.code_22)
                        }
                            break
                        case 30: {
                            this.instance.descriptionType.setValue(Description_type.code_30)
                        }
                            break
                        case 40: {
                            this.instance.descriptionType.setValue(Description_type.code_40)
                        }
                            break
                        case 41: {
                            this.instance.descriptionType.setValue(Description_type.code_41)
                        }
                            break
                        case 42: {
                            this.instance.descriptionType.setValue(Description_type.code_42)
                        }
                            break
                        case 43: {
                            this.instance.descriptionType.setValue(Description_type.code_43)
                        }
                            break
                        case 44: {
                            this.instance.descriptionType.setValue(Description_type.code_44)
                        }
                            break
                        case 45: {
                            this.instance.descriptionType.setValue(Description_type.code_45)
                        }
                            break
                        case 46: {
                            this.instance.descriptionType.setValue(Description_type.code_46)
                        }
                            break
                        case 47: {
                            this.instance.descriptionType.setValue(Description_type.code_47)
                        }
                            break
                        case 48: {
                            this.instance.descriptionType.setValue(Description_type.code_48)
                        }
                            break
                        case 49: {
                            this.instance.descriptionType.setValue(Description_type.code_49)
                        }
                            break
                        case 50: {
                            this.instance.descriptionType.setValue(Description_type.code_50)
                        }
                            break
                        case 51: {
                            this.instance.descriptionType.setValue(Description_type.code_51)
                        }
                            break
                        case 60: {
                            this.instance.descriptionType.setValue(Description_type.code_60)
                        }
                            break
                        case 70: {
                            this.instance.descriptionType.setValue(Description_type.code_70)
                        }
                            break
                        case 71: {
                            this.instance.descriptionType.setValue(Description_type.code_71)
                        }
                            break
                        case 80: {
                            this.instance.descriptionType.setValue(Description_type.code_80)
                        }
                            break
                        case 86: {
                            this.instance.descriptionType.setValue(Description_type.code_86)
                        }
                            break
                        case 90: {
                            this.instance.descriptionType.setValue(Description_type.code_90)
                        }
                            break
                        case 100: {
                            this.instance.descriptionType.setValue(Description_type.code_100)
                        }
                            break
                        case 110: {
                            this.instance.descriptionType.setValue(Description_type.code_110)
                        }
                            break
                        case 111: {
                            this.instance.descriptionType.setValue(Description_type.code_111)
                        }
                            break
                        case 112: {
                            this.instance.descriptionType.setValue(Description_type.code_112)
                        }
                            break
                        case 113: {
                            this.instance.descriptionType.setValue(Description_type.code_113)
                        }
                            break
                        case 114: {
                            this.instance.descriptionType.setValue(Description_type.code_114)
                        }
                            break
                        case 115: {
                            this.instance.descriptionType.setValue(Description_type.code_115)
                        }
                            break
                        case 116: {
                            this.instance.descriptionType.setValue(Description_type.code_116)
                        }
                            break
                        case 120: {
                            this.instance.descriptionType.setValue(Description_type.code_120)
                        }
                            break
                        case 255: {
                            this.instance.descriptionType.setValue(Description_type.code_255)
                        }
                            break
                        default: {
                            this.instance.descriptionType.setValue(BufferToUInt8(this.readBytes(6, 1)))
                        }
                    }
                },
                encode: (): void => {
                    const type: string = this.instance.descriptionType.getValue('0', (nodePath: string): void => this.recordError(nodePath, 'Not found'))
                    switch (type) {
                        case Description_type.code_0: {
                            const type: Buffer = UInt8ToBuffer(0)
                            this.writeBytes(6, type)
                        }
                            break
                        case Description_type.code_10: {
                            const type: Buffer = UInt8ToBuffer(10)
                            this.writeBytes(6, type)
                        }
                            break
                        case Description_type.code_20: {
                            const type: Buffer = UInt8ToBuffer(20)
                            this.writeBytes(6, type)
                        }
                            break
                        case Description_type.code_21: {
                            const type: Buffer = UInt8ToBuffer(21)
                            this.writeBytes(6, type)
                        }
                            break
                        case Description_type.code_22: {
                            const type: Buffer = UInt8ToBuffer(22)
                            this.writeBytes(6, type)
                        }
                            break
                        case Description_type.code_30: {
                            const type: Buffer = UInt8ToBuffer(30)
                            this.writeBytes(6, type)
                        }
                            break
                        case Description_type.code_40: {
                            const type: Buffer = UInt8ToBuffer(40)
                            this.writeBytes(6, type)
                        }
                            break
                        case Description_type.code_41: {
                            const type: Buffer = UInt8ToBuffer(41)
                            this.writeBytes(6, type)
                        }
                            break
                        case Description_type.code_42: {
                            const type: Buffer = UInt8ToBuffer(42)
                            this.writeBytes(6, type)
                        }
                            break
                        case Description_type.code_43: {
                            const type: Buffer = UInt8ToBuffer(43)
                            this.writeBytes(6, type)
                        }
                            break
                        case Description_type.code_44: {
                            const type: Buffer = UInt8ToBuffer(44)
                            this.writeBytes(6, type)
                        }
                            break
                        case Description_type.code_45: {
                            const type: Buffer = UInt8ToBuffer(45)
                            this.writeBytes(6, type)
                        }
                            break
                        case Description_type.code_46: {
                            const type: Buffer = UInt8ToBuffer(46)
                            this.writeBytes(6, type)
                        }
                            break
                        case Description_type.code_47: {
                            const type: Buffer = UInt8ToBuffer(47)
                            this.writeBytes(6, type)
                        }
                            break
                        case Description_type.code_48: {
                            const type: Buffer = UInt8ToBuffer(48)
                            this.writeBytes(6, type)
                        }
                            break
                        case Description_type.code_49: {
                            const type: Buffer = UInt8ToBuffer(49)
                            this.writeBytes(6, type)
                        }
                            break
                        case Description_type.code_50: {
                            const type: Buffer = UInt8ToBuffer(50)
                            this.writeBytes(6, type)
                        }
                            break
                        case Description_type.code_51: {
                            const type: Buffer = UInt8ToBuffer(51)
                            this.writeBytes(6, type)
                        }
                            break
                        case Description_type.code_60: {
                            const type: Buffer = UInt8ToBuffer(60)
                            this.writeBytes(6, type)
                        }
                            break
                        case Description_type.code_70: {
                            const type: Buffer = UInt8ToBuffer(70)
                            this.writeBytes(6, type)
                        }
                            break
                        case Description_type.code_71: {
                            const type: Buffer = UInt8ToBuffer(71)
                            this.writeBytes(6, type)
                        }
                            break
                        case Description_type.code_80: {
                            const type: Buffer = UInt8ToBuffer(80)
                            this.writeBytes(6, type)
                        }
                            break
                        case Description_type.code_86: {
                            const type: Buffer = UInt8ToBuffer(86)
                            this.writeBytes(6, type)
                        }
                            break
                        case Description_type.code_90: {
                            const type: Buffer = UInt8ToBuffer(90)
                            this.writeBytes(6, type)
                        }
                            break
                        case Description_type.code_100: {
                            const type: Buffer = UInt8ToBuffer(100)
                            this.writeBytes(6, type)
                        }
                            break
                        case Description_type.code_110: {
                            const type: Buffer = UInt8ToBuffer(110)
                            this.writeBytes(6, type)
                        }
                            break
                        case Description_type.code_111: {
                            const type: Buffer = UInt8ToBuffer(111)
                            this.writeBytes(6, type)
                        }
                            break
                        case Description_type.code_112: {
                            const type: Buffer = UInt8ToBuffer(112)
                            this.writeBytes(6, type)
                        }
                            break
                        case Description_type.code_113: {
                            const type: Buffer = UInt8ToBuffer(113)
                            this.writeBytes(6, type)
                        }
                            break
                        case Description_type.code_114: {
                            const type: Buffer = UInt8ToBuffer(114)
                            this.writeBytes(6, type)
                        }
                            break
                        case Description_type.code_115: {
                            const type: Buffer = UInt8ToBuffer(115)
                            this.writeBytes(6, type)
                        }
                            break
                        case Description_type.code_116: {
                            const type: Buffer = UInt8ToBuffer(116)
                            this.writeBytes(6, type)
                        }
                            break
                        case Description_type.code_120: {
                            const type: Buffer = UInt8ToBuffer(120)
                            this.writeBytes(6, type)
                        }
                            break
                        case Description_type.code_255: {
                            const type: Buffer = UInt8ToBuffer(255)
                            this.writeBytes(6, type)
                        }
                            break
                        default: {
                            const type1: number = parseInt(type, 10)
                            const type2: Buffer = UInt8ToBuffer(type1)
                            this.writeBytes(6, type2)
                        }
                    }
                }
            }


        }
    }
    public id: string = 'tls-alert'
    public name: string = 'Transport Layer Security(Alert Protocol)'
    public nickname: string = 'TLS-Alert'

    public match(): boolean {
        if (!this.prevCodecModule) return false
        const type: number = BufferToInt8(this.readBytes(0, 1))
        if (type != 21) return false
        const version: number = BufferToUInt16(this.readBytes(1, 2))
        const validVersions: number[] = [768, 769, 770, 771, 772]
        return validVersions.includes(version)
    }
}
