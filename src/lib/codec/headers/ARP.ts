import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {BaseHeader} from '../abstracts/BaseHeader'
import {UInt16ToHex, UInt8ToHex} from '../../helper/NumberToHex'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'
import {HexToUInt16} from '../../helper/HexToNumber'
import {BufferToInt16, BufferToUInt16, BufferToUInt8} from '../../helper/BufferToNumber'
import {BufferToHex} from '../../helper/BufferToHex'
import {UInt16ToBuffer, UInt8ToBuffer} from '../../helper/NumberToBuffer'
import {BufferToIPv4} from '../../helper/BufferToIP'
import {IPv4ToBuffer} from '../../helper/IPToBuffer'

export class ARP extends BaseHeader {

    public SCHEMA: ProtocolJSONSchema = {
        type: 'object',
        properties: {
            hardware: {
                type: 'object',
                label: 'Hardware',
                properties: {
                    type: {
                        type: 'number',
                        label: 'Type',
                        minimum: 0,
                        maximum: 65535,
                        decode: (): void => {
                            this.instance.hardware.type.setValue(BufferToInt16(this.readBytes(0, 2)))
                        },
                        encode: (): void => {
                            let hwType: number = this.instance.hardware.type.getValue(0, (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                            if (hwType > 65535) {
                                this.recordError(this.instance.hardware.type.getPath(), 'Maximum value is 65535')
                                hwType = 65535
                            }
                            if (hwType < 0) {
                                this.recordError(this.instance.hardware.type.getPath(), 'Minimum value is 0')
                                hwType = 0
                            }
                            this.instance.hardware.type.setValue(hwType)
                            this.writeBytes(0, UInt16ToBuffer(hwType))
                        }
                    },
                    size: {
                        type: 'number',
                        label: 'Size',
                        minimum: 0,
                        maximum: 255,
                        decode: (): void => {
                            this.instance.hardware.size.setValue(BufferToUInt8(this.readBytes(4, 1)))
                        },
                        encode: (): void => {
                            let hwSize: number = this.instance.hardware.size.getValue(0, (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                            if (hwSize > 255) {
                                this.recordError(this.instance.hardware.size.getPath(), 'Maximum value is 255')
                                hwSize = 255
                            }
                            if (hwSize < 0) {
                                this.recordError(this.instance.hardware.size.getPath(), 'Minimum value is 0')
                                hwSize = 0
                            }
                            this.instance.hardware.size.setValue(hwSize)
                            this.writeBytes(4, UInt8ToBuffer(hwSize))
                        }
                    }
                }
            },
            protocol: {
                type: 'object',
                label: 'Protocol',
                properties: {
                    type: {
                        type: 'string',
                        label: 'Type',
                        minLength: 4,
                        maxLength: 4,
                        contentEncoding: StringContentEncodingEnum.HEX,
                        decode: (): void => {
                            this.instance.protocol.type.setValue(BufferToHex(this.readBytes(2, 2)))
                        },
                        encode: (): void => {
                            let protoTypeHex: string = this.instance.protocol.type.getValue('0000', (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                            let protoType: number = HexToUInt16(protoTypeHex)
                            if (isNaN(protoType)) {
                                this.recordError(this.instance.protocol.type.getPath(), 'Invalid hex value')
                                protoType = 0
                            }
                            this.instance.protocol.type.setValue(protoType)
                            this.writeBytes(2, UInt16ToBuffer(protoType))
                        }
                    },
                    size: {
                        type: 'number',
                        label: 'Size',
                        minimum: 0,
                        maximum: 255,
                        decode: (): void => {
                            this.instance.protocol.size.setValue(BufferToUInt8(this.readBytes(5, 1)))
                        },
                        encode: (): void => {
                            let protoSize: number = this.instance.protocol.size.getValue(0, (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                            if (protoSize > 255) {
                                this.recordError(this.instance.protocol.size.getPath(), 'Maximum value is 255')
                                protoSize = 255
                            }
                            if (protoSize < 0) {
                                this.recordError(this.instance.protocol.size.getPath(), 'Minimum value is 0')
                                protoSize = 0
                            }
                            this.instance.protocol.size.setValue(protoSize)
                            this.writeBytes(5, UInt8ToBuffer(protoSize))
                        }
                    }
                }
            },
            opcode: {
                type: 'number',
                label: 'Opcode',
                enum: [1, 2, 3, 4],
                decode: (): void => {
                    this.instance.opcode.setValue(BufferToUInt16(this.readBytes(6, 2)))
                    if (![1, 2, 3, 4].includes(this.instance.opcode.getValue())) this.recordError(this.instance.opcode.getPath(), 'Opcode should be 1, 2, 3 or 4')
                },
                encode: (): void => {
                    let opcode: number = this.instance.opcode.getValue(0, (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                    if (![1, 2, 3, 4].includes(opcode)) this.recordError(this.instance.opcode.getPath(), 'Opcode should be 1, 2, 3 or 4')
                    this.instance.opcode.setValue(opcode)
                    this.writeBytes(6, UInt16ToBuffer(opcode))
                }
            },
            sender: {
                type: 'object',
                label: 'Sender',
                properties: {
                    mac: {
                        type: 'string',
                        label: 'MAC address',
                        minLength: 17,
                        maxLength: 17,
                        contentEncoding: StringContentEncodingEnum.UTF8,
                        decode: (): void => {
                            const macAddrBuffer: Buffer = Buffer.alloc(6, this.readBytes(8, 6))
                            this.instance.sender.mac.setValue(Array.from(macAddrBuffer).map((value: number): string => UInt8ToHex(value)).join(':'))
                        },
                        encode: (): void => {
                            let macStr: string = this.instance.sender.mac.getValue()
                            const rawMacBuffer: Buffer = Buffer.from(macStr.split(':').map((value: string): number => parseInt(value, 16)).map((value: number): number => value ? value : 0))
                            if (rawMacBuffer.length !== 6) this.recordError(this.instance.sender.mac.getPath(), 'Invalid MAC address length')
                            this.writeBytes(8, Buffer.alloc(6, rawMacBuffer))
                        }
                    },
                    ipv4: {
                        type: 'string',
                        label: 'IP address',
                        minLength: 7,
                        maxLength: 15,
                        contentEncoding: StringContentEncodingEnum.UTF8,
                        decode: (): void => {
                            const ipv4Buffer: Buffer = Buffer.alloc(4, this.readBytes(14, 4))
                            this.instance.sender.ipv4.setValue(BufferToIPv4(ipv4Buffer))
                        },
                        encode: (): void => {
                            let ipv4Str: string = this.instance.sender.ipv4.getValue()
                            this.writeBytes(14, IPv4ToBuffer(ipv4Str))
                        }
                    }
                }
            },
            target: {
                type: 'object',
                label: 'Target',
                properties: {
                    mac: {
                        type: 'string',
                        label: 'MAC address',
                        minLength: 17,
                        maxLength: 17,
                        contentEncoding: StringContentEncodingEnum.UTF8,
                        decode: (): void => {
                            const macAddrBuffer: Buffer = Buffer.alloc(6, this.readBytes(18, 6))
                            this.instance.target.mac.setValue(Array.from(macAddrBuffer).map((value: number): string => UInt8ToHex(value)).join(':'))
                        },
                        encode: (): void => {
                            let macStr: string = this.instance.target.mac.getValue()
                            const rawMacBuffer: Buffer = Buffer.from(macStr.split(':').map((value: string): number => parseInt(value, 16)).map((value: number): number => value ? value : 0))
                            if (rawMacBuffer.length !== 6) this.recordError(this.instance.target.mac.getPath(), 'Invalid MAC address length')
                            this.writeBytes(18, Buffer.alloc(6, rawMacBuffer))
                        }
                    },
                    ipv4: {
                        type: 'string',
                        label: 'IP address',
                        minLength: 7,
                        maxLength: 15,
                        contentEncoding: StringContentEncodingEnum.UTF8,
                        decode: (): void => {
                            const ipv4Buffer: Buffer = Buffer.alloc(4, this.readBytes(24, 4))
                            this.instance.target.ipv4.setValue(BufferToIPv4(ipv4Buffer))
                        },
                        encode: (): void => {
                            let ipv4Str: string = this.instance.target.ipv4.getValue()
                            this.writeBytes(24, IPv4ToBuffer(ipv4Str))
                        }
                    }
                }
            }
        }
    }

    public readonly id: string = 'arp'

    public readonly name: string = 'Address Resolution Protocol'

    public readonly nickname: string = 'ARP'

    public match(): boolean {
        if (!this.prevCodecModule) return false
        return this.prevCodecModule.instance.etherType.getValue() === UInt16ToHex(0x0806)
    }

}
