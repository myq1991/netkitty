import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {BaseHeader} from '../abstracts/BaseHeader'
import {UInt16ToHex, UInt8ToHex} from '../lib/NumberToHex'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'
import {HexToUInt16, HexToUInt8} from '../lib/HexToNumber'

export default class ARP extends BaseHeader {

    public SCHEMA: ProtocolJSONSchema = {
        properties: {
            hardware: {
                type: 'object',
                label: 'Hardware',
                decode: (): void => {
                    this.instance.hardware = {}
                },
                properties: {
                    type: {
                        type: 'number',
                        label: 'Type',
                        minimum: 0,
                        maximum: 65535,
                        decode: (): void => {
                            this.instance.hardware['type'] = HexToUInt16(this.readBytes(0, 2).toString('hex'))
                        },
                        encode: (): void => {
                            let hwType: number = this.instance.hardware['type'] as number
                            if (hwType === undefined) this.recordError('hardware.type', 'Not Found')
                            hwType = hwType ? hwType : 0
                            if (hwType > 65535) {
                                this.recordError('hardware.type', 'Maximum value is 65535')
                                hwType = 65535
                            }
                            if (hwType < 0) {
                                this.recordError('hardware.type', 'Minimum value is 0')
                                hwType = 0
                            }
                            this.writeBytes(0, Buffer.from(UInt16ToHex(hwType), 'hex'))
                        }
                    },
                    size: {
                        type: 'number',
                        label: 'Size',
                        minimum: 0,
                        maximum: 255,
                        decode: (): void => {
                            this.instance.hardware['size'] = HexToUInt8(this.readBytes(4, 1).toString('hex'))
                        },
                        encode: (): void => {
                            let hwSize: number = this.instance.hardware['size'] as number
                            if (hwSize === undefined) this.recordError('hardware.size', 'Not Found')
                            hwSize = hwSize ? hwSize : 0
                            if (hwSize > 255) {
                                this.recordError('hardware.size', 'Maximum value is 255')
                                hwSize = 255
                            }
                            if (hwSize < 0) {
                                this.recordError('hardware.size', 'Minimum value is 0')
                                hwSize = 0
                            }
                            this.writeBytes(4, Buffer.from(UInt8ToHex(hwSize), 'hex'))
                        }
                    }
                }
            },
            protocol: {
                type: 'object',
                label: 'Protocol',
                decode: (): void => {
                    this.instance.protocol = {}
                },
                properties: {
                    type: {
                        type: 'string',
                        label: 'Type',
                        minLength: 4,
                        maxLength: 4,
                        contentEncoding: StringContentEncodingEnum.HEX,
                        decode: (): void => {
                            this.instance.protocol['type'] = this.readBytes(2, 2).toString('hex')
                        },
                        encode: (): void => {
                            let protoTypeHex: string = this.instance.protocol['type'] as string
                            if (protoTypeHex === undefined) this.recordError('protocol.type', 'Not Found')
                            let protoType: number = HexToUInt16(protoTypeHex)
                            protoType = protoType ? protoType : 0
                            this.writeBytes(2, Buffer.from(UInt16ToHex(protoType), 'hex'))
                        }
                    },
                    size: {
                        type: 'number',
                        label: 'Size',
                        minimum: 0,
                        maximum: 255,
                        decode: (): void => {
                            this.instance.protocol['size'] = HexToUInt8(this.readBytes(5, 1).toString('hex'))
                        },
                        encode: (): void => {
                            let protoSize: number = this.instance.protocol['size'] as number
                            if (protoSize === undefined) this.recordError('protocol.size', 'Not Found')
                            protoSize = protoSize ? protoSize : 0
                            if (protoSize > 255) {
                                this.recordError('protocol.size', 'Maximum value is 255')
                                protoSize = 255
                            }
                            if (protoSize < 0) {
                                this.recordError('protocol.size', 'Minimum value is 0')
                                protoSize = 0
                            }
                            this.writeBytes(5, Buffer.from(UInt8ToHex(protoSize), 'hex'))
                        }
                    }
                }
            },
            opcode: {
                type: 'number',
                label: 'Opcode',
                enum: [1, 2, 3, 4],
                decode: (): void => {
                    this.instance.opcode = HexToUInt16(this.readBytes(6, 2).toString('hex'))
                    if (![1, 2, 3, 4].includes(this.instance.opcode)) this.recordError('opcode', 'Opcode should be 1, 2, 3 or 4')
                },
                encode: (): void => {
                    let opcode: number = this.instance.opcode as number
                    if (opcode === undefined) this.recordError('opcode', 'Not Found')
                    opcode = opcode ? opcode : 0
                    if (![1, 2, 3, 4].includes(opcode)) this.recordError('opcode', 'Opcode should be 1, 2, 3 or 4')
                    this.writeBytes(6, Buffer.from(UInt16ToHex(opcode), 'hex'))
                }
            },
            sender: {
                type: 'object',
                label: 'Sender',
                decode: (): void => {
                    this.instance.sender = {}
                },
                properties: {
                    mac: {
                        type: 'string',
                        label: 'MAC address',
                        minLength: 17,
                        maxLength: 17,
                        contentEncoding: StringContentEncodingEnum.UTF8,
                        decode: (): void => {
                            const macAddrBuffer: Buffer = Buffer.alloc(6, this.readBytes(8, 6))
                            this.instance.sender['mac'] = Array.from(macAddrBuffer).map((value: number): string => UInt8ToHex(value)).join(':')
                        },
                        encode: (): void => {
                            let macStr: string = this.instance.sender['mac'] as string
                            const rawMacBuffer: Buffer = Buffer.from(macStr.split(':').map((value: string): number => parseInt(value, 16)).map((value: number): number => value ? value : 0))
                            if (rawMacBuffer.length !== 6) this.recordError('sender.mac', 'Invalid MAC address length')
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
                            this.instance.sender['ipv4'] = Array.from(ipv4Buffer).join('.')
                        },
                        encode: (): void => {
                            let ipv4Str: string = this.instance.sender['ipv4'] as string
                            const rawIPv4Buffer: Buffer = Buffer.from(ipv4Str.split('.').map((value: string): number => parseInt(value)))
                            if (rawIPv4Buffer.length !== 4) this.recordError('sender.ipv4', 'Invalid IPv4 address length')
                            this.writeBytes(14, Buffer.alloc(4, rawIPv4Buffer))
                        }
                    }
                }
            },
            target: {
                type: 'object',
                label: 'Target',
                decode: (): void => {
                    this.instance.target = {}
                },
                properties: {
                    mac: {
                        type: 'string',
                        label: 'MAC address',
                        minLength: 17,
                        maxLength: 17,
                        contentEncoding: StringContentEncodingEnum.UTF8,
                        decode: (): void => {
                            const macAddrBuffer: Buffer = Buffer.alloc(6, this.readBytes(18, 6))
                            this.instance.target['mac'] = Array.from(macAddrBuffer).map((value: number): string => UInt8ToHex(value)).join(':')
                        },
                        encode: (): void => {
                            let macStr: string = this.instance.target['mac'] as string
                            const rawMacBuffer: Buffer = Buffer.from(macStr.split(':').map((value: string): number => parseInt(value, 16)).map((value: number): number => value ? value : 0))
                            if (rawMacBuffer.length !== 6) this.recordError('target.mac', 'Invalid MAC address length')
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
                            this.instance.target['ipv4'] = Array.from(ipv4Buffer).join('.')
                        },
                        encode: (): void => {
                            let ipv4Str: string = this.instance.target['ipv4'] as string
                            const rawIPv4Buffer: Buffer = Buffer.from(ipv4Str.split('.').map((value: string): number => parseInt(value)))
                            if (rawIPv4Buffer.length !== 4) this.recordError('target.ipv4', 'Invalid IPv4 address length')
                            this.writeBytes(24, Buffer.alloc(4, rawIPv4Buffer))
                        }
                    }
                }
            }
        }
    }

    public id: string = 'arp'

    public name: string = 'ARP'

    public match(): boolean {
        if (!this.prevCodecModule) return false
        return this.prevCodecModule.instance.etherType === UInt16ToHex(0x0806)
    }

}
