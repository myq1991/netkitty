import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {BufferToUInt8} from '../../helper/BufferToNumber'
import {BufferToHex} from '../../helper/BufferToHex'
import {HexToBuffer} from '../../helper/HexToBuffer'
import {BaseHeader} from '../abstracts/BaseHeader'
import {UInt8ToBuffer} from '../../helper/NumberToBuffer'


export class IEC104_S_Frame extends BaseHeader {
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
                    const controlType: number = this.readBits(2, 1, 7, 1)
                    switch (controlType) {
                        case 1: {
                            this.instance.apciType.setValue('S-Format')
                        }
                            break
                        default: {
                            this.recordError(this.instance.apciType.getPath(), 'Illegal acpiType!')
                            this.instance.apciType.setValue(controlType)
                        }
                    }
                },
                encode: (): void => {
                    const controlType: string = this.instance.apciType.getValue('0', (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                    switch (controlType) {
                        case 'S-Format': {
                            this.writeBits(2, 1, 7, 1, 1)
                        }
                            break
                        default: {
                            this.writeBits(2, 1, 7, 1, this.instance.apciType.getValue(0, (nodePath: string): void => this.recordError(nodePath, 'Not Found')))
                        }
                    }
                }
            }
        }
    }
    public id: string = 'IEC104_S_Frame'
    public name: string = 'IEC 60870-5-104'
    public nickname: string = 'iec60870_104'

    public match(): boolean {
        if (!this.prevCodecModules) return false
        if (BufferToUInt8(this.readBytes(0, 1)) != 104) return false
        const type: number = this.readBits(2, 1, 6, 2)
        switch (type) {
            case 1: {
                return true
            }
            default: {
                return false
            }
        }
    };
}