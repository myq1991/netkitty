import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {BaseHeader} from '../abstracts/BaseHeader'
import {BufferToInt8, BufferToUInt16} from '../../helper/BufferToNumber'
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

export class TLS_ApplicationData extends BaseHeader {
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
            appData: {
                type: 'string',
                label: 'Encrypted Application Data',
                minimum: 0,
                maximum: 65535,
                decode: (): void => {
                    this.instance.appData.setValue(BufferToHex(this.readBytes(5, this.instance.length.getValue())))

                },
                encode: (): void => {
                    const appData: Buffer = HexToBuffer(this.instance.appData.getValue('0', (nodePath: string): void => this.recordError(nodePath, 'Not found')))
                    this.writeBytes(5, appData)
                }
            }
        }
    }
    public id: string = 'tls-appdata'
    public name: string = 'Transport Layer Security(Application Data Protocol)'
    public nickname: string = 'TLS-AppData'

    public match(): boolean {
        if (!this.prevCodecModule) return false
        if (BufferToHex(this.readBytes(0, 1)) != '17') return false
        const version: number = BufferToUInt16(this.readBytes(1, 2))
        const validVersions: number[] = [768, 769, 770, 771, 772]
        return validVersions.includes(version)
    }

}