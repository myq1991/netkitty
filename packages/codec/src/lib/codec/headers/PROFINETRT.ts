import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../../helper/BufferToHex'
import {HexToBuffer} from '../../helper/HexToBuffer'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'

/**
 * PROFINET Real-Time (PROFINET-RT / PN-IO cyclic) — IEC 61158-6-10 / IEC 61784, carried directly in an
 * Ethernet II frame with EtherType 0x8892 (an Ethernet child — no IP/UDP). The frame opens with a 2-byte
 * big-endian FrameID that identifies the frame's type/purpose; the FrameID value ranges select the class
 * of traffic (0x0100-0x06FF isochronous RT_CLASS_3, 0x8000-0xBFFF cyclic RT_CLASS_1/2, 0xFC00-0xFCFF DCP,
 * 0xFF00-0xFF43 acyclic/alarms, etc.). Everything after the FrameID is the frame's data.
 *
 * For cyclic frames the data is the IO data followed — at the very end, before any Ethernet padding — by
 * a 4-byte APDU-Status (CycleCounter uint16 BE, DataStatus, TransferStatus). Because trailing Ethernet
 * padding on short frames sits AFTER the APDU-Status, splitting it out reliably needs the true data
 * length (from the GSD / IO configuration), which this minimal slice does not have. So everything after
 * the FrameID is kept verbatim as `data` (hex) and re-emitted untouched, so every frame — cyclic or
 * acyclic — round-trips byte-for-byte. Structuring the APDU-Status (and distinguishing it from padding)
 * is a deferred slice. PROFINET-RT is a leaf here — nothing demuxes above it.
 */
export class PROFINETRT extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (PROFINETRT.#schemaCache ??= PROFINETRT.#buildSchema())
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'PROFINET-RT frameId=${frameId}',
            properties: {
                frameId: this.fieldUInt('frameId', 0, 2, 'Frame ID'),
                //Everything after the 2-byte FrameID, kept verbatim as hex so the IO data + APDU-Status
                //(+ any Ethernet padding) round-trip byte-for-byte. Structuring the APDU-Status is a
                //deferred slice (see the class doc): it cannot be split from trailing padding without the
                //true data length from the IO configuration.
                data: {
                    type: 'string',
                    label: 'Data',
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: PROFINETRT): void {
                        const remaining: number = this.packet.length - this.startPos
                        this.instance.data.setValue(remaining > 2 ? BufferToHex(this.readBytes(2, remaining - 2)) : '')
                    },
                    encode: function (this: PROFINETRT): void {
                        const data: string = this.instance.data.getValue('')
                        if (data) this.writeBytes(2, HexToBuffer(data))
                    }
                }
            }
        }
    }

    public readonly id: string = 'pnio'

    public readonly name: string = 'PROFINET Real-Time'

    public readonly nickname: string = 'PROFINET-RT'

    public readonly matchKeys: string[] = ['ethertype:8892']

    public match(): boolean {
        //An Ethernet child selected by EtherType 0x8892 (stored as a lowercase 4-hex string). Require the
        //2-byte minimum for the FrameID.
        if (!this.prevCodecModule || this.prevCodecModule.id !== 'eth') return false
        if (this.prevCodecModule.instance.etherType.getValue() !== '8892') return false
        return this.packet.length - this.startPos >= 2
    }

    //A leaf header — nothing demuxes above PROFINET-RT.
    public readonly demuxProducers: DemuxProducer[] = []

}
