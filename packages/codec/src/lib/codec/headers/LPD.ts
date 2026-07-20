import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {CodecModule} from '../types/CodecModule'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../../helper/BufferToHex'
import {HexToBuffer} from '../../helper/HexToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/** Human-readable names for the LPD command codes (RFC 1179 §5 daemon commands + §6 receive-job subcommands). */
const LPD_COMMANDS: Readonly<Record<number, string>> = {
    0x01: 'Print any waiting jobs',
    0x02: 'Receive a printer job',
    0x03: 'Send queue state (short)',
    0x04: 'Send queue state (long)',
    0x05: 'Remove jobs'
}

/**
 * LPD / LPR — the Line Printer Daemon protocol (RFC 1179), the classic BSD print-spooling protocol
 * carried over TCP port 515. A command message is US-ASCII text: a single 1-byte command code followed
 * by operands (ASCII, space-separated — typically the queue name, and for some commands a user/job
 * list) terminated by a line feed (0x0A). The daemon commands are 0x01 "Print any waiting jobs",
 * 0x02 "Receive a printer job", 0x03/0x04 "Send queue state" (short/long), 0x05 "Remove jobs"; inside a
 * receive-job session the same 1-byte-code framing carries the sub-commands (abort / receive control
 * file / receive data file), followed by the transferred file bytes.
 *
 * Like SIP/HTTP, an LPD stream mixes a short command line with arbitrary (and, for the data-transfer
 * sub-commands, binary) file content whose framing spans TCP segments — richer than a form needs and
 * whitespace-significant. So the ENTIRE payload is kept verbatim as the authoritative `message` field
 * (hex) and re-emitted untouched (byte-perfect for any LPD message); only the leading command byte and
 * its operand line are parsed on decode into display-only metadata (command / commandName / operands),
 * which carry no codec of their own — encode never reconstructs the message from them. The payload is
 * bounded by the enclosing IP datagram (not the whole frame) so a short command does not swallow
 * Ethernet padding; any trailing bytes fall through to the codec's recursion / RawData.
 */
export class LPD extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (LPD.#schemaCache ??= LPD.#buildSchema())
    }

    /**
     * Bytes of this LPD layer: LPD rides on TCP (no per-message length), so the payload is the rest of
     * the segment — but bounded by the enclosing IPv4/IPv6 datagram so a small command line does not
     * absorb Ethernet padding (min-frame zero padding after a short IP packet). The TCP payload =
     * IP payload − TCP header length; trailing bytes past that are left to the codec's recursion.
     */
    #payloadLength(): number {
        let available: number = this.packet.length - this.startPos
        const tcp: CodecModule | undefined = this.prevCodecModule
        if (tcp) {
            //Walk back to the enclosing IP layer (skip the TCP module itself at the tail).
            const modules: CodecModule[] = this.prevCodecModules
            for (let i: number = modules.length - 2; i >= 0; i--) {
                const module: any = modules[i]
                if (module.id === 'ipv4') {
                    const tcpPayload: number = (module.instance.length.getValue(0) - module.length) - tcp.length
                    if (tcpPayload >= 0 && tcpPayload < available) available = tcpPayload
                    break
                }
                if (module.id === 'ipv6') {
                    const tcpPayload: number = module.instance.plen.getValue(0) - tcp.length
                    if (tcpPayload >= 0 && tcpPayload < available) available = tcpPayload
                    break
                }
            }
        }
        return available < 0 ? 0 : available
    }

    /**
     * Parse the display-only metadata from the payload: the leading command byte, its human-readable
     * name, and the operand text (the ASCII bytes after the command byte up to the first line feed).
     * Populated on decode only — these fields have no encode, so they never affect the re-emitted bytes.
     * Never throws: an empty payload yields command 0 / empty operands.
     */
    #parseCommand(raw: Buffer): void {
        const command: number = raw.length > 0 ? raw[0] : 0
        this.instance.command.setValue(command)
        this.instance.commandName.setValue(LPD_COMMANDS[command] ? LPD_COMMANDS[command] : '')
        let end: number = raw.indexOf(0x0a, 1)
        if (end < 0) end = raw.length
        this.instance.operands.setValue(raw.length > 1 ? raw.subarray(1, end).toString('latin1') : '')
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'LPD command=${command}',
            properties: {
                //The whole raw payload is the single source of truth: decoded verbatim to hex and
                //re-emitted untouched (byte-perfect for any LPD message). The command byte + operand line
                //are parsed into the display-only metadata below, which carry no codec of their own.
                message: {
                    type: 'string',
                    label: 'Message',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: LPD): void {
                        const available: number = this.#payloadLength()
                        if (available <= 0) {
                            this.instance.message.setValue('')
                            this.#parseCommand(Buffer.alloc(0))
                            return
                        }
                        const raw: Buffer = this.readBytes(0, available)
                        this.instance.message.setValue(BufferToHex(raw))
                        this.#parseCommand(raw)
                    },
                    encode: function (this: LPD): void {
                        //Re-emit the authoritative payload verbatim — never reconstruct from metadata.
                        this.writeBytes(0, HexToBuffer(this.instance.message.getValue('')))
                    }
                },
                //Display-only metadata parsed from the payload on decode (no encode — populated by the
                //message field above, never read back). command is the 1-byte code, commandName its
                //RFC 1179 label, operands the ASCII operand line up to the first line feed.
                command: {type: 'integer', label: 'Command', minimum: 0, maximum: 255},
                commandName: {type: 'string', label: 'Command Name'},
                operands: {type: 'string', label: 'Operands'}
            }
        }
    }

    public readonly id: string = 'lpd'

    public readonly name: string = 'Line Printer Daemon Protocol'

    public readonly nickname: string = 'LPD'

    public readonly matchKeys: string[] = ['tcpport:515']

    public match(): boolean {
        //LPD rides on TCP port 515 (selected via the tcpport:515 bucket). This stays a port-bucket
        //protocol: matchKeys only, NO heuristicFallback — a leading 1-byte command code is far too weak
        //a signature to claim LPD off port 515, and non-LPD traffic on 515 must fall through to raw. Guard
        //on port + a valid command code (0x01..0x05) followed by an ASCII operand line ending in a line
        //feed (LF), so binary/garbage on 515 is not claimed. Bounded by the transport payload (not the
        //whole frame) so Ethernet padding is not mistaken for the command line.
        if (!this.prevCodecModule || this.prevCodecModule.id !== 'tcp') return false
        const available: number = this.#payloadLength()
        if (available < 2) return false
        const scan: number = available < 256 ? available : 256
        const lead: Buffer = this.readBytes(0, scan, true)
        const command: number = lead[0]
        if (command < 0x01 || command > 0x05) return false
        //The operand bytes (after the command code, up to the first LF) must be printable ASCII, and a
        //terminating LF must be present within the scanned window.
        for (let i: number = 1; i < lead.length; i++) {
            const byte: number = lead[i]
            if (byte === 0x0a) return true
            if (byte < 0x20 || byte > 0x7e) return false
        }
        return false
    }

    //A leaf header — the transferred control/data file bytes of a receive-job session are kept verbatim.
    public readonly demuxProducers: DemuxProducer[] = []

}
