import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../../helper/BufferToHex'
import {HexToBuffer} from '../../helper/HexToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/** The Interpret As Command escape (RFC 854): every in-band command begins with this byte. */
const IAC: number = 0xFF

/** SE — the byte that ends a subnegotiation (paired as `IAC SE`, i.e. FF F0). */
const SE: number = 0xF0

/** A display-only parse of one leading IAC command sequence (never re-encoded — the message owns the bytes). */
type TelnetCommand = {
    command: number
    commandName: string
    option?: number
    optionName?: string
}

/** Command byte → mnemonic (RFC 854 §Commands; 255 is the escaped-IAC data byte, shown as "IAC"). */
const COMMAND_NAMES: Record<number, string> = {
    240: 'SE', 241: 'NOP', 242: 'DM', 243: 'BRK', 244: 'IP', 245: 'AO', 246: 'AYT',
    247: 'EC', 248: 'EL', 249: 'GA', 250: 'SB', 251: 'WILL', 252: 'WONT', 253: 'DO',
    254: 'DONT', 255: 'IAC'
}

/** Common Telnet option codes → name (display only; unknown options resolve to ''). */
const OPTION_NAMES: Record<number, string> = {
    0: 'Binary Transmission', 1: 'Echo', 3: 'Suppress Go Ahead', 5: 'Status',
    6: 'Timing Mark', 24: 'Terminal Type', 31: 'Window Size (NAWS)', 32: 'Terminal Speed',
    33: 'Remote Flow Control', 34: 'Linemode', 35: 'X Display Location', 36: 'Environment Option',
    39: 'New Environment Option'
}

/**
 * Telnet — the Telnet Protocol (RFC 854), carried over TCP well-known port 23. Telnet is a raw byte
 * stream that interleaves user data with in-band control commands. A command is introduced by the IAC
 * (Interpret As Command) escape 0xFF and is followed by a command byte:
 *
 *   241 NOP · 242 DM · 243 BRK · 244 IP · 245 AO · 246 AYT · 247 EC · 248 EL · 249 GA   (2-byte commands)
 *   251 WILL · 252 WONT · 253 DO · 254 DONT                                             (3-byte: FF <cmd> <option>)
 *   250 SB … 240 SE                                                                     (subnegotiation, ends at FF F0)
 *   255                                                                                 (escaped IAC — a literal 0xFF DATA byte)
 *
 * MINIMAL slice (mirrors the SSH/RFB verbatim-message pattern): the connection is a stream with no
 * per-message framing, so the ENTIRE payload is the single source of truth — decoded verbatim to hex in
 * the authoritative `message` field and re-emitted byte-for-byte on encode. On top of that, the leading
 * run of IAC command sequences is parsed into DISPLAY-ONLY metadata: `commands` (an array of
 * {command, option?}) and `isNegotiation` (true when the payload opens with an IAC byte). Those carry no
 * codec of their own and never reconstruct the bytes — the message owns them. So any Telnet payload
 * (option negotiation, subnegotiation, plain data, or a truncated fragment) round-trips exactly.
 *
 * Matching rationale (NO heuristicFallback): Telnet is claimed ONLY on the tcp:23 bucket. Telnet has NO
 * distinctive off-port content signature — it is an arbitrary byte stream (a leading IAC is common but
 * optional, and in binary mode the data can be anything), so recognizing it relies entirely on the
 * well-known port. Joining the global content-heuristic chain would therefore let Telnet mislabel
 * arbitrary TCP payloads on any port. Confining Telnet to tcp:23 keeps that impossible; alt-port Telnet
 * is rare and falls losslessly to raw. For the same reason match() deliberately does NOT gate on a
 * leading IAC or printable text: on the port-23 bucket every payload IS Telnet (including binary-mode
 * data), so any non-empty payload is kept verbatim rather than dropped to raw.
 */
export class Telnet extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (Telnet.#schemaCache ??= Telnet.#buildSchema())
    }

    /** Bytes available to this header: Telnet rides on TCP, which has no per-message length. */
    #payloadLength(): number {
        const available: number = this.packet.length - this.startPos
        return available < 0 ? 0 : available
    }

    /**
     * Parse the leading run of IAC command sequences into the display-only `commands` array and set
     * `isNegotiation`. Populated on decode only — these fields have no encode, so they never affect the
     * re-emitted bytes and never mutate `message`. Never throws: a dangling/truncated IAC simply stops
     * the walk, and a payload with no leading IAC yields an empty list.
     */
    #parseCommands(raw: Buffer): void {
        const len: number = raw.length
        this.instance.isNegotiation.setValue(len >= 1 && raw[0] === IAC)
        const commands: TelnetCommand[] = []
        let offset: number = 0
        while (offset < len && raw[offset] === IAC) {
            //A dangling IAC at end-of-buffer is not a complete command — stop.
            if (offset + 1 >= len) break
            const cmd: number = raw[offset + 1]
            //IAC IAC is an ESCAPED 0xFF data byte, not a command — the command run ends here.
            if (cmd === IAC) break
            const commandName: string = COMMAND_NAMES[cmd] ?? 'Unknown'
            if (cmd >= 251 && cmd <= 254) {
                //WILL/WONT/DO/DONT — a 3-byte command carrying an option byte.
                if (offset + 2 >= len) break
                const option: number = raw[offset + 2]
                commands.push({command: cmd, commandName: commandName, option: option, optionName: OPTION_NAMES[option] ?? ''})
                offset += 3
            } else if (cmd === 250) {
                //SB — subnegotiation: `FF FA <option> …params… FF F0`. Capture the option, then skip to
                //just past the terminating IAC SE (or to end-of-buffer if it is unterminated/truncated).
                const option: number | undefined = offset + 2 < len ? raw[offset + 2] : undefined
                const entry: TelnetCommand = {command: cmd, commandName: commandName}
                if (option !== undefined) {
                    entry.option = option
                    entry.optionName = OPTION_NAMES[option] ?? ''
                }
                commands.push(entry)
                let se: number = -1
                for (let i: number = offset + 2; i + 1 < len; i++) {
                    if (raw[i] === IAC && raw[i + 1] === SE) {
                        se = i
                        break
                    }
                }
                if (se === -1) break
                offset = se + 2
            } else {
                //240 SE / 241..249 — a 2-byte command with no option.
                commands.push({command: cmd, commandName: commandName})
                offset += 2
            }
        }
        this.instance.commands.setValue(commands)
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'Telnet',
            properties: {
                //Display-only metadata parsed from the leading IAC command run on decode (no encode —
                //populated by the `message` field below, never read back). isNegotiation flags a payload
                //that opens with an IAC byte; commands lists the leading command sequences for the UI.
                isNegotiation: {type: 'boolean', label: 'Is Negotiation', default: false},
                commands: {
                    type: 'array',
                    label: 'IAC Commands',
                    items: {
                        type: 'object',
                        label: 'Command',
                        properties: {
                            command: {type: 'integer', label: 'Command', minimum: 0, maximum: 255},
                            commandName: {type: 'string', label: 'Command Name'},
                            option: {type: 'integer', label: 'Option', minimum: 0, maximum: 255},
                            optionName: {type: 'string', label: 'Option Name'}
                        }
                    }
                },
                //The whole raw payload is the single source of truth: decoded verbatim to hex and
                //re-emitted untouched (byte-perfect for any Telnet payload). The leading IAC command run is
                //parsed into the display-only metadata above, which carry no codec of their own.
                message: {
                    type: 'string',
                    label: 'Message',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    default: '',
                    decode: function (this: Telnet): void {
                        const available: number = this.#payloadLength()
                        if (available <= 0) {
                            this.instance.message.setValue('')
                            this.#parseCommands(Buffer.alloc(0))
                            return
                        }
                        const raw: Buffer = this.readBytes(0, available)
                        this.instance.message.setValue(BufferToHex(raw))
                        this.#parseCommands(raw)
                    },
                    encode: function (this: Telnet): void {
                        //Re-emit the authoritative payload verbatim — never reconstruct from metadata.
                        this.writeBytes(0, HexToBuffer(this.instance.message.getValue('')))
                    }
                }
            }
        }
    }

    public readonly id: string = 'telnet'

    public readonly name: string = 'Telnet'

    public readonly nickname: string = 'Telnet'

    //Telnet is recognized ONLY on the well-known port 23 — deliberately NOT via heuristicFallback. Telnet
    //is a raw byte stream with no distinctive off-port content signature (a leading IAC is common but
    //optional, and binary-mode data is arbitrary), so its recognition depends entirely on the port bucket;
    //joining the global heuristic chain would mislabel arbitrary TCP traffic. See the class doc.
    public readonly matchKeys: string[] = ['tcpport:23']

    public match(): boolean {
        //Reached only on the tcp:23 bucket. Port 23 IS Telnet's, so any non-empty payload over TCP is
        //claimed and kept verbatim (byte-perfect) — deliberately without an IAC/printable gate, so
        //binary-mode Telnet data is never wrongly dropped to raw. An empty payload is not claimed.
        if (!this.prevCodecModule) return false
        if (this.prevCodecModule.id !== 'tcp') return false
        return this.#payloadLength() >= 1
    }

    //A leaf header — the Telnet byte stream is the terminal session itself; nothing demuxes off it.
    public readonly demuxProducers: DemuxProducer[] = []

}
