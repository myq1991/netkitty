import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {BaseHeader} from '../abstracts/BaseHeader'
import {BufferToUInt16} from '../../helper/BufferToNumber'
import {UInt16ToBuffer, UInt8ToBuffer} from '../../helper/NumberToBuffer'
import {IPv6ToBuffer} from '../../helper/IPToBuffer'
import {CodecModule} from '../types/CodecModule'

export class UDP extends BaseHeader {

    /**
     * Calculate UDP Checksum
     * @protected
     * @param udpHeaderBuffer
     */
    protected calculateUDPChecksum(udpHeaderBuffer: Buffer): number {
        const udpHeaderLength: number = udpHeaderBuffer.length
        const ipVersion: number = this.prevCodecModule.instance.version.getValue()
        let pseudoHeaderBuffer: Buffer = Buffer.from([])
        const sourceIp: string = this.prevCodecModule.instance.sip.getValue()
        const destinationIp: string = this.prevCodecModule.instance.dip.getValue()
        if (ipVersion === 4) {
            //4 Bytes
            const sourceIPv4Buffer: Buffer = Buffer.from(sourceIp.split('.').map((value: string): number => parseInt(value)))
            const destinationIPv4Buffer: Buffer = Buffer.from(destinationIp.split('.').map((value: string): number => parseInt(value)))
            //IPv4 Pseudo header
            pseudoHeaderBuffer = Buffer.concat([
                sourceIPv4Buffer,
                destinationIPv4Buffer,
                UInt8ToBuffer(0), //Reserved field
                UInt8ToBuffer(17), //Protocol type (UDP = 17)
                Buffer.from([(udpHeaderLength >> 8) & 0xFF]),
                Buffer.from([udpHeaderLength & 0xFF])
            ])
        } else if (ipVersion === 6) {
            //16 Bytes
            const sourceIPv6Buffer: Buffer = IPv6ToBuffer(sourceIp)
            const destinationIPv6Buffer: Buffer = IPv6ToBuffer(destinationIp)
            //IPv6 Pseudo header
            pseudoHeaderBuffer = Buffer.concat([
                sourceIPv6Buffer,
                destinationIPv6Buffer,
                UInt8ToBuffer(0), //Reserved field
                UInt8ToBuffer(0), //Reserved field
                UInt8ToBuffer(0), //Reserved field
                UInt8ToBuffer(17), //Protocol type (UDP = 17)
                Buffer.from([(udpHeaderLength >> 8) & 0xFF]),
                Buffer.from([udpHeaderLength & 0xFF])
            ])
        } else {
            return 0
        }
        let dataBuffer: Buffer = Buffer.concat([pseudoHeaderBuffer, udpHeaderBuffer])
        if (dataBuffer.length % 2) dataBuffer = Buffer.concat([dataBuffer, Buffer.from('00', 'hex')])
        const data: Uint8Array = Uint8Array.from(dataBuffer)
        let sum: number = 0
        for (let i: number = 0; i < data.length; i += 2) sum += (data[i] << 8) + (data[i + 1] || 0)
        while (sum > 0xFFFF) sum = (sum & 0xFFFF) + (sum >>> 16)
        return (~sum) & 0xFFFF
    }

    public SCHEMA: ProtocolJSONSchema = {
        type: 'object',
        properties: {
            srcport: {
                type: 'integer',
                label: 'Source Port',
                minimum: 0,
                maximum: 65535,
                decode: (): void => {
                    this.instance.srcport.setValue(BufferToUInt16(this.readBytes(0, 2)))
                },
                encode: (): void => {
                    let srcport: number = this.instance.srcport.getValue(0, (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                    if (srcport > 65535) {
                        this.recordError(this.instance.srcport.getPath(), 'Maximum value is 65535')
                        srcport = 65535
                    }
                    if (srcport < 0) {
                        this.recordError(this.instance.srcport.getPath(), 'Minimum value is 0')
                        srcport = 0
                    }
                    this.instance.srcport.setValue(srcport)
                    this.writeBytes(0, UInt16ToBuffer(srcport))
                }
            },
            dstport: {
                type: 'integer',
                label: 'Destination Port',
                minimum: 0,
                maximum: 65535,
                decode: (): void => {
                    this.instance.dstport.setValue(BufferToUInt16(this.readBytes(2, 2)))
                },
                encode: (): void => {
                    let dstport: number = this.instance.dstport.getValue(0, (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                    if (dstport > 65535) {
                        this.recordError(this.instance.dstport.getPath(), 'Maximum value is 65535')
                        dstport = 65535
                    }
                    if (dstport < 0) {
                        this.recordError(this.instance.dstport.getPath(), 'Minimum value is 0')
                        dstport = 0
                    }
                    this.instance.dstport.setValue(dstport)
                    this.writeBytes(2, UInt16ToBuffer(dstport))
                }
            },
            length: {
                type: 'integer',
                label: 'Length',
                minimum: 0,
                maximum: 65535,
                decode: (): void => {
                    this.instance.length.setValue(BufferToUInt16(this.readBytes(4, 2)))
                },
                encode: (): void => {
                    let length: number = this.instance.length.getValue(0)
                    if (length) {
                        this.instance.length.setValue(length)
                        this.writeBytes(4, UInt16ToBuffer(length))
                    } else {
                        this.instance.length.setValue(length)
                        this.writeBytes(4, UInt16ToBuffer(length))
                        this.addPostPacketEncodeHandler((): void => {
                            let startCount: boolean = false
                            let udpLength: number = 0
                            this.codecModules.forEach((codecModule: CodecModule): void => {
                                if (codecModule === this) startCount = true
                                if (startCount) udpLength += codecModule.length
                            })
                            this.instance.length.setValue(udpLength)
                            this.writeBytes(4, UInt16ToBuffer(udpLength))
                        }, 1)
                    }
                }
            },
            checksum: {
                type: 'integer',
                label: 'Checksum',
                minimum: 0,
                maximum: 65535,
                decode: (): void => {
                    this.instance.checksum.setValue(BufferToUInt16(this.readBytes(6, 2)))
                },
                encode: (): void => {
                    const checksum: number = this.instance.checksum.getValue(0)
                    if (checksum) {
                        this.instance.checksum.setValue(checksum)
                        this.writeBytes(6, UInt16ToBuffer(checksum))
                    } else {
                        this.writeBytes(6, UInt16ToBuffer(checksum))
                        this.instance.checksum.setValue(checksum)
                        this.addPostPacketEncodeHandler((): void => {
                            let startCount: boolean = false
                            let udpHeaderWithDataLength: number = 0
                            this.codecModules.forEach((codecModule: CodecModule): void => {
                                if (codecModule === this) startCount = true
                                if (startCount) udpHeaderWithDataLength += codecModule.length
                            })
                            const calcChecksum: number = this.calculateUDPChecksum(this.packet.subarray(this.startPos, this.startPos + udpHeaderWithDataLength))
                            this.instance.checksum.setValue(calcChecksum)
                            this.writeBytes(6, UInt16ToBuffer(calcChecksum))
                        }, 2)
                    }
                }
            }
        }
    }

    public readonly id: string = 'udp'

    public readonly name: string = 'User Datagram Protocol'

    public readonly nickname: string = 'UDP'

    public match(): boolean {
        if (!this.prevCodecModule) return false
        if (this.prevCodecModule.instance.protocol.getValue() === 0x11) return true
        return false
    }

}
