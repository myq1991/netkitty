import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../helper/BufferToHex'
import {BufferToUInt8} from '../helper/BufferToNumber'
import {UInt8ToBuffer} from '../helper/NumberToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/**
 * One DHCP option. `code` + verbatim hex `value`. Pad (0) and End (255) are single-byte options with
 * no length/value (their `value` is absent). Every other option is code(1)+len(1)+value(len).
 */
type DhcpOption = {
    code: number
    value?: string
}

/**
 * DHCP — Dynamic Host Configuration Protocol (RFC 2131), built on the BOOTP message format (RFC 951).
 * A 236-byte fixed header (op/htype/hlen/hops, xid, secs, flags, the four IP addresses, 16-byte client
 * hardware address, 64-byte server name and 128-byte boot file name), then the 4-byte magic cookie
 * 0x63825363 (RFC 2131 §3), then variable options in code-length-value form (§9) terminated by End
 * (255). Rides UDP, ports 67 (server) and 68 (client).
 *
 * Options are carried generically (code + verbatim hex value) so every option — standard or unknown —
 * round-trips byte-for-byte; per-option semantic decoding is a later enrichment. sname/file/chaddr are
 * kept as raw hex (they contain fixed-width zero padding an editor must preserve). Any bytes after the
 * End option (the BOOTP minimum-size padding) fall to the following raw layer.
 */
export class DHCP extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (DHCP.#schemaCache ??= DHCP.#buildSchema())
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            properties: {
                op: this.fieldUInt('op', 0, 1, 'Message Type'),
                htype: this.fieldUInt('htype', 1, 1, 'Hardware Type'),
                hlen: this.fieldUInt('hlen', 2, 1, 'Hardware Address Length'),
                hops: this.fieldUInt('hops', 3, 1, 'Hops'),
                xid: this.fieldUInt('xid', 4, 4, 'Transaction ID'),
                secs: this.fieldUInt('secs', 8, 2, 'Seconds Elapsed'),
                flags: this.fieldUInt('flags', 10, 2, 'Flags'),
                ciaddr: this.fieldIPv4('ciaddr', 12, 'Client IP Address'),
                yiaddr: this.fieldIPv4('yiaddr', 16, 'Your IP Address'),
                siaddr: this.fieldIPv4('siaddr', 20, 'Next Server IP Address'),
                giaddr: this.fieldIPv4('giaddr', 24, 'Relay Agent IP Address'),
                chaddr: this.fieldHex('chaddr', 28, 16, 'Client Hardware Address'),
                sname: this.fieldHex('sname', 44, 64, 'Server Host Name'),
                file: this.fieldHex('file', 108, 128, 'Boot File Name'),
                magicCookie: this.fieldHex('magicCookie', 236, 4, 'Magic Cookie'),
                options: {
                    type: 'array',
                    label: 'Options',
                    items: {
                        type: 'object',
                        label: 'Option',
                        properties: {
                            code: {
                                type: 'integer',
                                label: 'Code',
                                minimum: 0,
                                maximum: 255
                            },
                            value: {
                                type: 'string',
                                label: 'Value',
                                contentEncoding: StringContentEncodingEnum.HEX
                            }
                        }
                    },
                    decode: function (this: DHCP): void {
                        //Options begin right after the 4-byte magic cookie (fixed 236 + 4 = 240).
                        const available: number = this.packet.length - this.startPos
                        const options: DhcpOption[] = []
                        let offset: number = 240
                        //Code(1) [Len(1) Value(Len)]. Pad(0) and End(255) are bare single bytes; End
                        //terminates the option block (trailing BOOTP padding falls to the raw layer).
                        //readBytes clamps at the buffer end and offset always advances, so a truncated
                        //or option-list-with-no-End packet cannot read out of bounds or loop forever.
                        while (offset < available) {
                            const code: number = BufferToUInt8(this.readBytes(offset, 1))
                            offset += 1
                            if (code === 0) {
                                options.push({code: 0})
                                continue
                            }
                            if (code === 255) {
                                options.push({code: 255})
                                break
                            }
                            //Need a length byte; if the buffer ends here, stop.
                            if (offset >= available) {
                                options.push({code: code})
                                break
                            }
                            const length: number = BufferToUInt8(this.readBytes(offset, 1))
                            offset += 1
                            let value: Buffer = Buffer.alloc(0)
                            if (length) {
                                value = this.readBytes(offset, length)
                                offset += length
                            }
                            options.push({code: code, value: BufferToHex(value)})
                        }
                        this.instance.options.setValue(options)
                    },
                    encode: function (this: DHCP): void {
                        const options: DhcpOption[] | undefined = this.instance.options.getValue()
                        if (!options) return
                        let offset: number = 240
                        options.forEach((option: DhcpOption): void => {
                            const code: number = option.code ? option.code : 0
                            this.writeBytes(offset, UInt8ToBuffer(code))
                            offset += 1
                            //Pad (0) and End (255): a single byte, no length/value.
                            if (code === 0 || code === 255) return
                            const value: Buffer = Buffer.from(option.value ? option.value : '', 'hex')
                            this.writeBytes(offset, UInt8ToBuffer(value.length))
                            offset += 1
                            if (value.length) {
                                this.writeBytes(offset, value)
                                offset += value.length
                            }
                        })
                    }
                }
            }
        }
    }

    public readonly id: string = 'dhcp'

    public readonly name: string = 'Dynamic Host Configuration Protocol'

    public readonly nickname: string = 'DHCP'

    //Server port 67 and client port 68 (both UDP). heuristicFallback because the 0x63825363 magic
    //cookie at offset 236 is a reliable 32-bit content signature.
    public readonly matchKeys: string[] = ['udpport:67', 'udpport:68']

    public readonly heuristicFallback: boolean = true

    public match(): boolean {
        if (!this.prevCodecModule) return false
        //Magic cookie 0x63825363 at offset 236 (RFC 2131 §3) — the fixed BOOTP header is always 236
        //bytes, so a valid DHCP message is at least 240 bytes.
        if (this.packet.length - this.startPos < 240) return false
        return BufferToHex(this.readBytes(236, 4)) === '63825363'
    }

    //A leaf header — nothing demuxes above DHCP.
    public readonly demuxProducers: DemuxProducer[] = []

}
