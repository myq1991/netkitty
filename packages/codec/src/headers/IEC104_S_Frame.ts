import {ProtocolJSONSchema} from '../schema/ProtocolJSONSchema'
import {BufferToUInt8} from '../helper/BufferToNumber'
import {BufferToHex} from '../helper/BufferToHex'
import {HexToBuffer} from '../helper/HexToBuffer'
import {BaseHeader} from '../abstracts/BaseHeader'
import {CodecModule} from '../types/CodecModule'
import {UInt8ToBuffer} from '../helper/NumberToBuffer'


/**
 * IEC 60870-5-104 S-format APCI — the "Supervisory" frame of IEC 104, which rides on TCP port 2404. Every
 * IEC 104 APDU begins with a 6-octet APCI: an 8-bit Start byte (`startByte`, offset 0, always 0x68 / 104),
 * an 8-bit APDU Length (`apduLength`, offset 1, the octet count that follows), and a 4-octet Control Field
 * (`controlField`, offset 2, kept verbatim as hex — the authoritative bytes). This codec covers the
 * S-format APDU, which carries no ASDU and exists only to acknowledge received I-frames: it additionally
 * exposes, read-only, the 15-bit Receive Sequence Number N(R) (`rxSequence`, decoded from control octets
 * 3-4 as a little-endian value right-shifted by 1) and an `apciType` label derived from the control-format
 * bits (set to "S-Format").
 *
 * `rxSequence` and `apciType` are display projections over the same bytes; `controlField` stays the encode
 * authority, so a captured frame round-trips byte-for-byte. In the heuristic chain (`heuristicFallback`),
 * match() requires a TCP peer on port 2404, a Start byte of 104, and the control format bits to select
 * S-format.
 */
export class IEC104_S_Frame extends BaseHeader {
    public SCHEMA: ProtocolJSONSchema = {
        type: 'object',
        properties: {
            startByte: {
                type: 'integer',
                label: 'Start Byte',
                minimum: 0,
                maximum: 255,
                decode: (): void => {
                    this.instance.startByte.setValue(BufferToUInt8(this.readBytes(0, 1)))
                },
                encode: (): void => {
                    this.writeBytes(0, UInt8ToBuffer(this.instance.startByte.getValue(0, (nodePath: string): void => this.recordError(nodePath, 'Not Found'))))
                }
            },
            apduLength: {
                type: 'integer',
                label: 'APDU Length',
                minimum: 0,
                maximum: 255,
                decode: (): void => {
                    this.instance.apduLength.setValue(BufferToUInt8(this.readBytes(1, 1)))
                },
                encode: (): void => {
                    this.writeBytes(1, UInt8ToBuffer(this.instance.apduLength.getValue(0, (nodePath: string): void => this.recordError(nodePath, 'Not Found'))))
                }
            },
            controlField: {
                type: 'string',
                label: 'Control Field',
                decode: (): void => {
                    this.instance.controlField.setValue(BufferToHex(this.readBytes(2, 4)))
                },
                encode: (): void => {
                    this.writeBytes(2, HexToBuffer(this.instance.controlField.getValue('0', (nodePath: string): void => this.recordError(nodePath, 'Not Found'))))
                }
            },
            //Receive sequence number N(R): a 15-bit value in control octets 3-4, stored
            //little-endian and left-shifted by 1. Exposed read-only for analysis (S-frames exist
            //precisely to acknowledge this sequence number); controlField holds the authoritative bytes.
            rxSequence: {
                type: 'integer',
                label: 'Rx Sequence Number N(R)',
                decode: (): void => {
                    this.instance.rxSequence.setValue(this.readBytes(4, 2).readUInt16LE() >> 1)
                }
            },
            apciType: {
                type: 'string',
                label: 'APCI Type',
                minimum: 0,
                maximum: 3,
                decode: (): void => {
                    const controlType: number = this.readBits(2, 1, 7, 1)
                    switch (controlType) {
                        case 1: {
                            this.instance.apciType.setValue('S-Format')
                        }
                            break
                        default: {
                            this.recordError(this.instance.apciType.getPath(), 'Illegal acpiType!')
                            this.instance.apciType.setValue(controlType)
                        }
                    }
                },
                encode: (): void => {
                    const controlType: string = this.instance.apciType.getValue('0', (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                    switch (controlType) {
                        case 'S-Format': {
                            this.writeBits(2, 1, 7, 1, 1)
                        }
                            break
                        default: {
                            this.writeBits(2, 1, 7, 1, this.instance.apciType.getValue(0, (nodePath: string): void => this.recordError(nodePath, 'Not Found')))
                        }
                    }
                }
            }
        }
    }
    public id: string = 'IEC104_S_Frame'
    public readonly matchKeys: string[] = ['tcpport:2404']
    public readonly heuristicFallback: boolean = true
    public name: string = 'IEC 60870-5-104'
    public nickname: string = 'iec60870_104'

    public match(): boolean {
        if (!this.prevCodecModules) return false
        //IEC 104 always rides on TCP port 2404 (see IEC104_I_Frame.match for rationale).
        if (!this.prevCodecModules.some((module: CodecModule): boolean =>
            module.id === 'tcp' && (module.instance.srcport.getValue() === 2404 || module.instance.dstport.getValue() === 2404))) return false
        if (BufferToUInt8(this.readBytes(0, 1)) != 104) return false
        const type: number = this.readBits(2, 1, 6, 2)
        switch (type) {
            case 1: {
                return true
            }
            default: {
                return false
            }
        }
    };
}