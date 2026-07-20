import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../../helper/BufferToHex'
import {HexToBuffer} from '../../helper/HexToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/**
 * Rlogin — the Remote Login protocol (RFC 1282), carried over TCP well-known port 513. After the TCP
 * connection opens, the client sends a single startup message: four null-separated strings
 *
 *   \0 {client-user-name} \0 {server-user-name} \0 {terminal-type}/{terminal-speed} \0
 *
 * e.g. `00 6a 64 6f 65 00 72 6f 6f 74 00 78 74 65 72 6d 2f 33 38 34 30 30 00`
 * ("\0jdoe\0root\0xterm/38400\0"). The leading null makes the first split field empty. After that startup
 * exchange the connection is an unframed byte stream (the server replies with a single 0x00 to accept,
 * then terminal data flows; interrupts and window-size changes ride in-band as URG/control bytes).
 *
 * MINIMAL slice (mirrors the SSH/Telnet/Finger verbatim-message pattern): the connection has no
 * per-message framing, so the ENTIRE payload is the single source of truth — decoded verbatim to hex in
 * the authoritative `message` field and re-emitted byte-for-byte on encode. On top of that, when the
 * payload opens with a 0x00 byte (the startup shape) the leading null-separated fields are parsed into
 * DISPLAY-ONLY metadata: `isStartup`, `clientUser`, `serverUser`, `terminalType` (the raw
 * "terminal/speed" field). Those carry no codec of their own and never reconstruct the bytes — the
 * message owns them. So any Rlogin payload (a startup message, the server's 0x00 ack, terminal data, or
 * a truncated fragment) round-trips exactly.
 *
 * Matching rationale (NO heuristicFallback): Rlogin is claimed ONLY on the tcp:513 bucket. The startup
 * message opens with a 0x00 byte, but that is a weak, generic signature (a leading null byte matches
 * countless binary payloads) and the ensuing byte stream has no content magic at all, so recognizing
 * Rlogin relies entirely on the well-known port. Joining the global content-heuristic chain would let
 * Rlogin mislabel arbitrary TCP payloads on any port. Confining Rlogin to tcp:513 keeps that impossible;
 * alt-port Rlogin is rare and falls losslessly to raw. For the same reason match() does NOT gate on a
 * leading null: on the port-513 bucket every payload IS Rlogin (including the byte-stream phase), so any
 * non-empty payload is kept verbatim rather than dropped to raw.
 */
export class Rlogin extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (Rlogin.#schemaCache ??= Rlogin.#buildSchema())
    }

    /** Bytes available to this header: Rlogin rides on TCP, which has no per-message length. */
    #payloadLength(): number {
        const available: number = this.packet.length - this.startPos
        return available < 0 ? 0 : available
    }

    /**
     * Parse the startup message into the display-only metadata fields. The startup message is
     * `\0 client-user \0 server-user \0 terminal-type/speed \0`, so splitting the payload on the null byte
     * yields ['', clientUser, serverUser, terminalType, …]. Populated on decode only — these fields have no
     * encode, so they never affect the re-emitted bytes and never mutate `message`. Never throws: a payload
     * that does not open with 0x00 (the byte-stream phase) yields isStartup false and empty fields.
     */
    #parseStartup(raw: Buffer): void {
        const isStartup: boolean = raw.length >= 1 && raw[0] === 0x00
        this.instance.isStartup.setValue(isStartup)
        if (!isStartup) {
            this.instance.clientUser.setValue('')
            this.instance.serverUser.setValue('')
            this.instance.terminalType.setValue('')
            this.instance.summaryInfo.setValue('data')
            return
        }
        //The leading null makes segments[0] the empty first field; the three named fields follow.
        const segments: string[] = raw.toString('latin1').split('\0')
        const clientUser: string = segments[1] !== undefined ? segments[1] : ''
        const serverUser: string = segments[2] !== undefined ? segments[2] : ''
        const terminalType: string = segments[3] !== undefined ? segments[3] : ''
        this.instance.clientUser.setValue(clientUser)
        this.instance.serverUser.setValue(serverUser)
        this.instance.terminalType.setValue(terminalType)
        this.instance.summaryInfo.setValue(clientUser || serverUser ? `${clientUser}/${serverUser}` : 'startup')
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'Rlogin ${summaryInfo}',
            properties: {
                //Display-only metadata parsed from the startup message on decode (no encode — populated by
                //the `message` field below, never read back). isStartup flags a payload that opens with a
                //0x00 byte; clientUser/serverUser/terminalType are the leading null-separated fields.
                isStartup: {type: 'boolean', label: 'Is Startup', default: false},
                clientUser: {type: 'string', label: 'Client User', default: ''},
                serverUser: {type: 'string', label: 'Server User', default: ''},
                terminalType: {type: 'string', label: 'Terminal Type', default: ''},
                //Drives the one-line summary: "clientUser/serverUser" for a startup, else 'data'.
                summaryInfo: {type: 'string', label: 'Summary', hidden: true, default: ''},
                //The whole raw payload is the single source of truth: decoded verbatim to hex and re-emitted
                //untouched (byte-perfect for any Rlogin payload). The startup fields are parsed into the
                //display-only metadata above, which carry no codec of their own.
                message: {
                    type: 'string',
                    label: 'Message',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    default: '',
                    decode: function (this: Rlogin): void {
                        const available: number = this.#payloadLength()
                        if (available <= 0) {
                            this.instance.message.setValue('')
                            this.#parseStartup(Buffer.alloc(0))
                            return
                        }
                        const raw: Buffer = this.readBytes(0, available)
                        this.instance.message.setValue(BufferToHex(raw))
                        this.#parseStartup(raw)
                    },
                    encode: function (this: Rlogin): void {
                        //Re-emit the authoritative payload verbatim — never reconstruct from metadata.
                        this.writeBytes(0, HexToBuffer(this.instance.message.getValue('')))
                    }
                }
            }
        }
    }

    public readonly id: string = 'rlogin'

    public readonly name: string = 'Rlogin'

    public readonly nickname: string = 'Rlogin'

    //Rlogin is recognized ONLY on the well-known port 513 — deliberately NOT via heuristicFallback. The
    //startup message opens with a weak, generic 0x00 byte and the ensuing byte stream has no content magic,
    //so its recognition depends entirely on the port bucket; joining the global heuristic chain would
    //mislabel arbitrary TCP traffic. See the class doc for the full rationale.
    public readonly matchKeys: string[] = ['tcpport:513']

    public match(): boolean {
        //Reached only on the tcp:513 bucket. Port 513 IS Rlogin's, so any non-empty payload over TCP is
        //claimed and kept verbatim (byte-perfect) — deliberately without a leading-null gate, so the
        //byte-stream phase is never wrongly dropped to raw. An empty payload is not claimed.
        if (!this.prevCodecModule) return false
        if (this.prevCodecModule.id !== 'tcp') return false
        return this.#payloadLength() >= 1
    }

    //A leaf header — the Rlogin byte stream is the terminal session itself; nothing demuxes off it.
    public readonly demuxProducers: DemuxProducer[] = []

}
