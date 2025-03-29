import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {BaseHeader} from '../abstracts/BaseHeader'
import {BufferToUInt16, BufferToUInt8} from '../lib/BufferToNumber'
import {UInt16ToBuffer, UInt8ToBuffer} from '../lib/NumberToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'
import {BufferToHex} from '../lib/BufferToHex'

export class ICMP extends BaseHeader {

    /**
     * Calculate ICMPv4 checksum
     * @protected
     */
    protected calculateIcmpChecksum(): number {
        const icmpHeader: Buffer = Buffer.concat([
            UInt8ToBuffer(this.instance.type.getValue(0)),
            UInt8ToBuffer(this.instance.code.getValue(0)),
            UInt16ToBuffer(this.instance.checksum.getValue(0)),
            UInt16ToBuffer(this.instance.ident.getValue(0)),
            UInt16ToBuffer(this.instance.seq.getValue(0)),
            Buffer.from(this.instance.message.getValue(''), 'hex')
        ])
        const paddedBuffer: Buffer = icmpHeader.length % 2 === 1 ?
            Buffer.concat([
                icmpHeader,
                UInt8ToBuffer(0)
            ]) : icmpHeader

        // 4. 计算 checksum
        let checksum = 0
        for (let i = 0; i < paddedBuffer.length; i += 2) {
            const word = (paddedBuffer[i] << 8) | (paddedBuffer[i + 1] || 0)
            checksum += word

            // 处理溢出
            if (checksum > 0xFFFF) {
                checksum = (checksum & 0xFFFF) + 1
            }
        }

        // 取反得到最终 checksum
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
                        checksum = this.calculateIcmpChecksum()
                        this.instance.checksum.setValue(checksum)
                        this.writeBytes(2, UInt16ToBuffer(checksum))
                    }
                }
            },
            ident: {
                type: 'number',
                label: 'Identifier (BE)',
                minimum: 0,
                maximum: 65535,
                decode: (): void => {
                    this.instance.ident.setValue(BufferToUInt16(this.readBytes(4, 2)))
                },
                encode: (): void => {
                    const ident: number = this.instance.ident.getValue(0, (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                    this.instance.ident.setValue(ident)
                    this.writeBytes(4, UInt16ToBuffer(ident))
                }
            },
            seq: {
                type: 'number',
                label: 'Sequence Number (BE)',
                minimum: 0,
                maximum: 65535,
                decode: (): void => {
                    this.instance.seq.setValue(BufferToUInt16(this.readBytes(6, 2)))
                },
                encode: (): void => {
                    const seq: number = this.instance.seq.getValue(0, (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                    this.instance.seq.setValue(seq)
                    this.writeBytes(6, UInt16ToBuffer(seq))
                }
            },
            message: {
                type: 'string',
                label: 'Message Body',
                contentEncoding: StringContentEncodingEnum.HEX,
                decode: (): void => {
                    const messageDataLength: number = this.packet.length - this.startPos - 8
                    this.instance.message.setValue(BufferToHex(this.readBytes(8, messageDataLength)))
                },
                encode: (): void => {
                    const messageHex: string = this.instance.message.getValue('')
                    this.instance.message.setValue(messageHex)
                    this.writeBytes(8, Buffer.from(messageHex, 'hex'))
                }
            }
        }
    }

    public id: string = 'icmp'

    public name: string = 'Internet Control Message Protocol'

    public nickname: string = 'ICMP'

    public match(): boolean {
        if (!this.prevCodecModule) return false
        return this.prevCodecModule.instance.protocol.getValue() === 0x01
    }

}
