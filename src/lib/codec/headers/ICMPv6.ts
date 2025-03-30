import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {BaseHeader} from '../abstracts/BaseHeader'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'
import {BufferToUInt16, BufferToUInt8} from '../../helper/BufferToNumber'
import {UInt16ToBuffer, UInt32ToBuffer, UInt8ToBuffer} from '../../helper/NumberToBuffer'
import {BufferToHex} from '../../helper/BufferToHex'
import {CodecModule} from '../types/CodecModule'
import {IPv6ToBuffer} from '../../helper/IPToBuffer'

export class ICMPv6 extends BaseHeader {

    /**
     * Calculate ICMPv6 checksum
     * @protected
     */
    protected calculateIcmpv6Checksum(): number {
        const ipv6Header: CodecModule | undefined = this.prevCodecModules.find((prevCodecModule: CodecModule): boolean => prevCodecModule.id === 'ipv6')
        if (!ipv6Header) return 0
        const messageBody: Buffer = Buffer.from(this.instance.message.getValue(''), 'hex')
        const sip: string = ipv6Header.instance.sip.getValue('0000:0000:0000:0000:0000:0000:0000:0000')
        const dip: string = ipv6Header.instance.dip.getValue('0000:0000:0000:0000:0000:0000:0000:0000')
        const pseudoHeader: Buffer = Buffer.concat([
            IPv6ToBuffer(sip),
            IPv6ToBuffer(dip),
            UInt32ToBuffer(messageBody.length + 4),
            UInt8ToBuffer(0x00),
            UInt8ToBuffer(0x00),
            UInt8ToBuffer(0x00),
            UInt8ToBuffer(0x3a)
        ])

        const icmpHeader: Buffer = Buffer.concat([
            UInt8ToBuffer(this.instance.type.getValue(0)),
            UInt8ToBuffer(this.instance.code.getValue(0)),
            UInt16ToBuffer(this.instance.checksum.getValue(0))
        ])
        const buffer: Buffer = Buffer.concat([
            pseudoHeader,
            icmpHeader,
            messageBody
        ])
        const paddedBuffer: Buffer = buffer.length % 2 === 1 ? Buffer.concat([buffer, UInt8ToBuffer(0)]) : buffer
        let checksum: number = 0
        for (let i: number = 0; i < paddedBuffer.length; i += 2) {
            checksum += (paddedBuffer[i] << 8) | (paddedBuffer[i + 1] || 0)
            if (checksum > 0xFFFF) checksum = (checksum & 0xFFFF) + 1
        }
        return (~checksum) & 0xFFFF
    }

    public SCHEMA: ProtocolJSONSchema = {
        type: 'object',
        properties: {
            type: {
                type: 'integer',
                label: 'Type',
                minimum: 0,
                maximum: 255,
                decode: (): void => {
                    this.instance.type.setValue(BufferToUInt8(this.readBytes(0, 1)))
                },
                encode: (): void => {
                    const type: number = this.instance.type.getValue(0, (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                    this.instance.type.setValue(type)
                    this.writeBytes(0, UInt8ToBuffer(type))
                }
            },
            code: {
                type: 'integer',
                label: 'Code',
                minimum: 0,
                maximum: 255,
                decode: (): void => {
                    this.instance.code.setValue(BufferToUInt8(this.readBytes(1, 1)))
                },
                encode: (): void => {
                    const code: number = this.instance.code.getValue(0, (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                    this.instance.code.setValue(code)
                    this.writeBytes(1, UInt8ToBuffer(code))
                }
            },
            checksum: {
                type: 'integer',
                label: 'Checksum',
                minimum: 0,
                maximum: 65535,
                decode: (): void => {
                    this.instance.checksum.setValue(BufferToUInt16(this.readBytes(2, 2)))
                },
                encode: (): void => {
                    let checksum: number = this.instance.checksum.getValue(0)
                    this.instance.checksum.setValue(checksum)
                    this.writeBytes(2, UInt16ToBuffer(checksum))
                    if (!checksum) {
                        checksum = this.calculateIcmpv6Checksum()
                        this.instance.checksum.setValue(checksum)
                        this.writeBytes(2, UInt16ToBuffer(checksum))
                    }
                }
            },
            message: {
                type: 'string',
                label: 'Message Body',
                contentEncoding: StringContentEncodingEnum.HEX,
                decode: (): void => {
                    const messageDataLength: number = this.packet.length - this.startPos - 4
                    this.instance.message.setValue(BufferToHex(this.readBytes(4, messageDataLength)))
                },
                encode: (): void => {
                    const messageHex: string = this.instance.message.getValue('')
                    this.instance.message.setValue(messageHex)
                    this.writeBytes(4, Buffer.from(messageHex, 'hex'))
                }
            }
        }
    }

    public id: string = 'icmpv6'

    public name: string = 'Internet Control Message Protocol v6'

    public nickname: string = 'ICMPv6'

    public match(): boolean {
        if (!this.prevCodecModule) return false
        return this.prevCodecModule.instance.nxt.getValue() === 0x3a
    }
}
