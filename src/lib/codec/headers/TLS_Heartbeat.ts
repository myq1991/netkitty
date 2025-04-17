import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {BaseHeader} from '../abstracts/BaseHeader'
import {BufferToUInt8, BufferToUInt16} from '../../helper/BufferToNumber'
import {HexToBuffer} from '../../helper/HexToBuffer'
import {BufferToHex} from '../../helper/BufferToHex'
import {UInt8ToBuffer, UInt16ToBuffer} from '../../helper/NumberToBuffer'

enum TLSver {
    SSL_3_0 = 'SSL3.0',
    TLS_1_0 = 'TLS1.0',
    TLS_1_1 = 'TLS1.1',
    TLS_1_2 = 'TLS1.2',
    TLS_1_3 = 'TLS1.3',
}

export class TLS_Heartbeat extends BaseHeader {
    public SCHEMA: ProtocolJSONSchema = {
        type: 'object',
        properties: {
            contentType: {
                type: 'integer',
                label: 'Content Type',
                minimum: 0,
                maximum: 255,
                decode: (): void => {
                    this.instance.contentType.setValue(BufferToUInt8(this.readBytes(0, 1)))
                },
                encode: (): void => {
                    const contentType: number = this.instance.contentType.getValue(0, (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                    this.writeBytes(0, UInt8ToBuffer(contentType))
                }
            },
            version: {
                type: 'string',
                label: 'Version',
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
                            this.instance.version.setValue(0)
                        }
                    }
                },
                encode: (): void => {
                    const version: string = this.instance.version.getValue('0', (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                    switch (version) {
                        case TLSver.SSL_3_0: {
                            this.writeBytes(1, UInt16ToBuffer(768))
                        }
                            break
                        case TLSver.TLS_1_0: {
                            this.writeBytes(1, UInt16ToBuffer(769))
                        }
                            break
                        case TLSver.TLS_1_1: {
                            this.writeBytes(1, UInt16ToBuffer(770))
                        }
                            break
                        case TLSver.TLS_1_2: {
                            this.writeBytes(1, UInt16ToBuffer(771))
                        }
                            break
                        case TLSver.TLS_1_3: {
                            this.writeBytes(1, UInt16ToBuffer(772))
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
                    const length: number = this.instance.length.getValue(0, (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                    this.writeBytes(3, UInt16ToBuffer(length))
                }
            },
            heartbeatType: {
                type: 'string',
                label: 'Heartbeat Type',
                minimum: 0,
                maximum: 255,
                decode: (): void => {
                    const heartbeatType: number = BufferToUInt8(this.readBytes(5, 1))
                    switch (heartbeatType) {
                        case 1: {
                            this.instance.heartbeatType.setValue('HeartbeatRequest')
                        }
                            break
                        case 2: {
                            this.instance.heartbeatType.setValue('HeartbeatResponse')
                        }
                            break
                        default: {
                            this.instance.heartbeatType.setValue(heartbeatType)
                        }
                    }
                },
                encode: (): void => {
                    const heartbeatType: string = this.instance.heartbeatType.getValue('0', (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                    switch (heartbeatType) {
                        case 'HeartbeatRequest': {
                            this.writeBytes(5, UInt8ToBuffer(1))
                        }
                            break
                        case 'HeartbeatResponse': {
                            this.writeBytes(5, UInt8ToBuffer(2))
                        }
                            break
                        default: {
                            const heartbeatType1: number = parseInt(heartbeatType)
                            this.writeBytes(5, UInt8ToBuffer(heartbeatType1))
                        }
                    }
                }
            },
            payloadLength: {
                type: 'integer',
                label: 'Payload Length',
                minimum: 0,
                maximum: 65535,
                decode: (): void => {
                    this.instance.payloadLength.setValue(BufferToUInt16(this.readBytes(6, 2)))
                },
                encode: (): void => {
                    const payloadLength: number = this.instance.payloadLength.getValue(0, (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                    this.writeBytes(6, UInt16ToBuffer(payloadLength))
                }
            },
            payloadMessage: {
                type: 'string',
                label: 'Payload Message',
                decode: (): void => {
                    const payloadLength: number = this.instance.payloadLength.getValue(0, (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                    const payloadMessage: string = BufferToHex(this.readBytes(8, payloadLength))
                    this.instance.payloadMessage.setValue(payloadMessage)
                },
                encode: (): void => {
                    const payloadMessage: string = this.instance.payloadMessage.getValue('0', (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                    this.writeBytes(8, HexToBuffer(payloadMessage))
                }

            }

        }
    }
    public id: string = 'tls-heartbeat'
    public name: string = 'Transport Layer Security(Heartbeat Protocol)'
    public nickname: string = 'TLS-Heartbeat'

    public match(): boolean {
        if (!this.prevCodecModule) return false
        if (BufferToHex(this.readBytes(0, 1)) != '18') return false
        const version: number = BufferToUInt16(this.readBytes(1, 2))
        const validVersions: number[] = [768, 769, 770, 771, 772]
        return validVersions.includes(version)
    }
}