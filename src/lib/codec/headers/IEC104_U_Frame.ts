import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {BufferToUInt8} from '../../helper/BufferToNumber'
import {BufferToHex} from '../../helper/BufferToHex'
import {HexToBuffer} from '../../helper/HexToBuffer'
import {BaseHeader} from '../abstracts/BaseHeader'
import {UInt32ToBuffer, UInt8ToBuffer} from '../../helper/NumberToBuffer'


export class IEC104_U_Frame extends BaseHeader {
    public SCHEMA: ProtocolJSONSchema = {
        type: 'object',
        properties: {
            startByte: {
                type: 'integer',
                label: 'Start Byte',
                minimum: 0,
                maximum: 255,
                decode: (): void => {
                    this.instance.startByte.setValue(BufferToUInt8(this.readBytes(0, 1)))
                },
                encode: (): void => {
                    this.writeBytes(0, UInt8ToBuffer(this.instance.startByte.getValue(0, (nodePath: string): void => this.recordError(nodePath, 'Not Found'))))
                }
            },
            apduLength: {
                type: 'integer',
                label: 'APDU Length',
                minimum: 0,
                maximum: 255,
                decode: (): void => {
                    this.instance.apduLength.setValue(BufferToUInt8(this.readBytes(1, 1)))
                },
                encode: (): void => {
                    this.writeBytes(1, UInt8ToBuffer(this.instance.apduLength.getValue(0, (nodePath: string): void => this.recordError(nodePath, 'Not Found'))))
                }
            },
            controlField: {
                type: 'string',
                label: 'Control Field',
                decode: (): void => {
                    this.instance.controlField.setValue(BufferToHex(this.readBytes(2, 4)))
                },
                encode: (): void => {
                    this.writeBytes(2, HexToBuffer(this.instance.controlField.getValue('0', (nodePath: string): void => this.recordError(nodePath, 'Not Found'))))
                }
            },
            apciType: {
                type: 'string',
                label: 'APCI Type',
                minimum: 0,
                maximum: 3,
                decode: (): void => {
                    const uframeType: string = BufferToHex(this.readBytes(2, 4))
                    switch (uframeType) {
                        case '43000000': {
                            this.instance.apciType.setValue('U-Format Type:Test Frame Activation')
                        }
                            break
                        case '83000000': {
                            this.instance.apciType.setValue('U-Format Type:Test Frame Confirmation')
                        }
                            break
                        case '13000000': {
                            this.instance.apciType.setValue('U-Format Type:Stop Data Transfer Activation')
                        }
                            break
                        case '23000000': {
                            this.instance.apciType.setValue('U-Format Type:Stop Data Transfer Confirmation')
                        }
                            break
                        case '07000000': {
                            this.instance.apciType.setValue('U-Format Type:Start Data Transfer Activation')
                        }
                            break
                        case '0B000000': {
                            this.instance.apciType.setValue('U-Format Type:Start Data Transfer Confirmation')
                        }
                            break
                        default: {
                            this.recordError(this.instance.apciType.getPath(), 'Illegal acpiType!')
                            this.instance.apciType.setValue(uframeType)
                        }
                    }
                },
                encode: (): void => {
                    const controlType: string = this.instance.apciType.getValue('0', (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                    switch (controlType) {
                        case 'U-Format Type:Test Frame Activation': {
                            this.writeBytes(2, UInt32ToBuffer(1124073472))
                        }
                            break
                        case 'U-Format Type:Test Frame Confirmation': {
                            this.writeBytes(2, UInt32ToBuffer(2197815296))
                        }
                            break
                        case 'U-Format Type:Stop Data Transfer Activation': {
                            this.writeBytes(2, UInt32ToBuffer(318767104))
                        }
                            break
                        case 'U-Format Type:Stop Data Transfer Confirmation': {
                            this.writeBytes(2, UInt32ToBuffer(587202560))
                        }
                            break
                        case 'U-Format Type:Start Data Transfer Activation': {
                            this.writeBytes(2, UInt32ToBuffer(117440512))
                        }
                            break
                        case 'U-Format Type:Start Data Transfer Confirmation': {
                            this.writeBytes(2, UInt32ToBuffer(184549376))
                        }
                            break
                        default: {
                            this.writeBytes(2, HexToBuffer(this.instance.apciType.getValue('0', (nodePath: string): void => this.recordError(nodePath, 'Not Found'))))
                        }
                    }
                }
            }


        }
    }
    public id: string = 'IEC104_U_Frame'
    public name: string = 'IEC 60870-5-104'
    public nickname: string = 'iec60870_104'

    public match(): boolean {
        if (!this.prevCodecModules) return false
        if (BufferToUInt8(this.readBytes(0, 1)) != 104) return false
        const type: number = this.readBits(2, 1, 6, 2)
        switch (type) {
            case 3: {
                return true
            }
            default: {
                return false
            }
        }
    };
}