import {ProtocolJSONSchema} from '../schema/ProtocolJSONSchema'
import {BufferToUInt8} from '../helper/BufferToNumber'
import {BufferToHex} from '../helper/BufferToHex'
import {HexToBuffer} from '../helper/HexToBuffer'
import {BaseHeader} from '../abstracts/BaseHeader'
import {CodecModule} from '../types/CodecModule'
import {UInt32ToBuffer, UInt8ToBuffer} from '../helper/NumberToBuffer'


/**
 * IEC 60870-5-104 U-format APCI — the "Unnumbered" control frame of IEC 104, which rides on TCP port 2404.
 * Like every IEC 104 APDU it begins with a 6-octet APCI: an 8-bit Start byte (`startByte`, offset 0,
 * always 0x68 / 104), an 8-bit APDU Length (`apduLength`, offset 1), and a 4-octet Control Field
 * (`controlField`, offset 2, kept verbatim as hex — the encode authority). U-format frames carry no ASDU
 * and no sequence numbers; they signal link control. This codec decodes an `apciType` label by matching
 * the whole 4-octet control field to one of the six defined U functions — Test Frame Activation
 * (43000000) / Confirmation (83000000), Stop Data Transfer Activation (13000000) / Confirmation
 * (23000000), and Start Data Transfer Activation (07000000) / Confirmation (0b000000) — and records an
 * error while keeping the raw hex for any other value.
 *
 * On encode a recognized `apciType` label writes back its fixed 4-octet control word, else the verbatim
 * hex is re-emitted, so a captured frame round-trips byte-for-byte. In the heuristic chain
 * (`heuristicFallback`), match() requires a TCP peer on port 2404, a Start byte of 104, and the control
 * format bits to select U-format.
 */
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
                        case '0b000000': {
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
    public readonly matchKeys: string[] = ['tcpport:2404']
    public readonly heuristicFallback: boolean = true
    public name: string = 'IEC 60870-5-104'
    public nickname: string = 'iec60870_104'

    public match(): boolean {
        if (!this.prevCodecModules) return false
        //IEC 104 always rides on TCP port 2404 (see IEC104_I_Frame.match for rationale).
        if (!this.prevCodecModules.some((module: CodecModule): boolean =>
            module.id === 'tcp' && (module.instance.srcport.getValue() === 2404 || module.instance.dstport.getValue() === 2404))) return false
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