import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {CodecModule} from '../types/CodecModule'
import {BufferToUInt16} from '../../helper/BufferToNumber'
import {UInt16ToBuffer} from '../../helper/NumberToBuffer'

/**
 * TPKT — the RFC 1006 "ISO Transport Service on top of TCP" packetization layer, TCP port 102. It is the
 * bottom of the IEC 61850 MMS / substation ISO stack: a fixed 4-byte header — Version (always 3), a
 * Reserved byte (usually 0), and a 2-byte big-endian Length — precedes the COTP TPDU (and above it the
 * ISO Session / Presentation / ACSE / MMS layers). The Length counts the WHOLE TPKT PDU, the 4-byte header
 * included, so `Length − 4` bytes of COTP-and-above follow.
 *
 * TPKT is not a leaf: it decodes only its 4 bytes (headerLength = 4) and the codec dispatches COTP next
 * (COTP is an unkeyed content-heuristic child gated on prev.id === 'tpkt'). The Length is honoured verbatim
 * when supplied — a crafted packet may carry any Length, which we reproduce faithfully — otherwise it is
 * derived at packet-post-encode time from this layer plus everything stacked above it (COTP + session/MMS),
 * mirroring how UDP derives its own Length. A well-formed frame round-trips byte-for-byte.
 */
export class TPKT extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (TPKT.#schemaCache ??= TPKT.#buildSchema())
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'TPKT v${version} len=${length}',
            properties: {
                version: this.fieldUInt('version', 0, 1, 'Version'),
                reserved: this.fieldUInt('reserved', 1, 1, 'Reserved'),
                length: {
                    type: 'integer',
                    label: 'Length',
                    minimum: 0,
                    maximum: 65535,
                    decode: function (this: TPKT): void {
                        this.instance.length.setValue(BufferToUInt16(this.readBytes(2, 2)))
                    },
                    encode: function (this: TPKT): void {
                        //The Length counts the entire TPKT PDU (the 4-byte header + the COTP-and-above
                        //bytes). Honour it verbatim when supplied (a crafted frame may lie); otherwise
                        //derive it after every layer has encoded, summing this header plus all layers
                        //stacked on top of it — the same approach UDP uses for its length.
                        const length: number = this.instance.length.getValue(0)
                        if (length) {
                            this.instance.length.setValue(length)
                            this.writeBytes(2, UInt16ToBuffer(length))
                        } else {
                            this.writeBytes(2, UInt16ToBuffer(0))
                            this.addPostPacketEncodeHandler((): void => {
                                let startCount: boolean = false
                                let total: number = 0
                                this.codecModules.forEach((codecModule: CodecModule): void => {
                                    if (codecModule === this) startCount = true
                                    if (startCount) total += codecModule.length
                                })
                                //The Length is a 16-bit field; a total beyond 65535 cannot be represented.
                                //Clamp and record rather than silently wrapping (mirrors the Ajv guard on
                                //the honored path). A real TPKT PDU physically cannot exceed 65535, so this
                                //only guards crafted over-length stacks.
                                if (total > 65535) {
                                    this.recordError(this.instance.length.getPath(), 'Maximum value is 65535')
                                    total = 65535
                                }
                                this.instance.length.setValue(total)
                                this.writeBytes(2, UInt16ToBuffer(total))
                            }, 1)
                        }
                    }
                }
            }
        }
    }

    public readonly id: string = 'tpkt'

    public readonly name: string = 'TPKT'

    public readonly nickname: string = 'TPKT'

    //TPKT rides on TCP port 102 (ISO-on-TCP / MMS / S7) and 3389 (RDP, which layers X.224 over TPKT).
    public readonly matchKeys: string[] = ['tcpport:102', 'tcpport:3389']

    public match(): boolean {
        //Selected via the tcpport:102 / tcpport:3389 buckets. Require the full 4-byte header and the
        //Version == 3 content signature so non-TPKT traffic on those ports falls through to raw.
        if (!this.prevCodecModule || this.prevCodecModule.id !== 'tcp') return false
        if (this.packet.length - this.startPos < 4) return false
        return this.readBytes(0, 1, true)[0] === 3
    }

    //Not a leaf, but it exposes no demux value: the codec routes COTP as an unkeyed content-heuristic
    //child that matches on prev.id === 'tpkt'.
    public readonly demuxProducers: DemuxProducer[] = []

}
