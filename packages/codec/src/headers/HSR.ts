import {ProtocolJSONSchema} from '../schema/ProtocolJSONSchema'
import {BaseHeader} from '../abstracts/BaseHeader'
import {DemuxProducer} from '../types/DemuxProducer'
import {UInt16ToHex} from '../helper/NumberToHex'
import {BufferToHex} from '../helper/BufferToHex'

export class HSR extends BaseHeader {
    public SCHEMA: ProtocolJSONSchema = {
        type: 'object',
        summary: 'HSR seq=${seqNr}',
        properties: {
            path: {
                type: 'integer',
                minimum: 0,
                maximum: 15,
                default: 0,
                label: 'Path',
                //Path (network id) and LSDUsize share the first 2 octets: Path is the top 4 bits,
                //LSDUsize the low 12 bits. writeBits masks its own field, so the two encode closures
                //overlay disjoint bit ranges into the same window without clobbering each other.
                decode: (): void => {
                    this.instance.path.setValue(this.readBits(0, 2, 0, 4))
                },
                encode: (): void => {
                    const pathValue: number = this.instance.path.getValue(0)
                    this.instance.path.setValue(pathValue)
                    this.writeBits(0, 2, 0, 4, pathValue)
                }
            },
            lsduSize: {
                type: 'integer',
                minimum: 0,
                maximum: 4095,
                default: 0,
                label: 'LSDU Size',
                //A plain read/write field: NOT used to bound the carried frame (the inner protocol
                //self-bounds via its own length semantics).
                decode: (): void => {
                    this.instance.lsduSize.setValue(this.readBits(0, 2, 4, 12))
                },
                encode: (): void => {
                    const lsduSizeValue: number = this.instance.lsduSize.getValue(0)
                    this.instance.lsduSize.setValue(lsduSizeValue)
                    this.writeBits(0, 2, 4, 12, lsduSizeValue)
                }
            },
            seqNr: BaseHeader.fieldUInt('seqNr', 2, 2, 'Sequence Number'),
            etherType: {
                type: 'string',
                minLength: 4,
                maxLength: 4,
                label: 'EtherType',
                //The ORIGINAL EtherType of the carried frame. MUST be named `etherType` and stored as a
                //lowercase 4-hex string exactly like VLAN/Ethernet, because L2 children (GOOSE, SV,
                //VLAN, ARP) discriminate by reading prevCodecModule.instance.etherType — a different
                //name would make them read undefined and fall through to RawData.
                decode: (): void => {
                    this.instance.etherType.setValue(BufferToHex(this.readBytes(4, 2)))
                },
                encode: (): void => {
                    const etherType: string = this.instance.etherType.getValue(UInt16ToHex(0x0000), (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                    const typeBuffer: Buffer = Buffer.from(etherType, 'hex')
                    if (typeBuffer.length < 2) typeBuffer.fill(0, 0, 1)
                    this.writeBytes(4, typeBuffer.subarray(0, 2))
                }
            }
        }
    }

    public readonly id: string = 'hsr'

    public readonly matchKeys: string[] = ['ethertype:892f']

    public readonly demuxProducers: DemuxProducer[] = [{field: 'etherType', namespace: 'ethertype', kind: 'string'}]

    public readonly name: string = 'High-availability Seamless Redundancy'

    public readonly nickname: string = 'HSR'

    public match(): boolean {
        //Like a VLAN tag, HSR is selected by the carrying layer's EtherType (0x892f) with no restriction
        //on which layer that is — so it rides directly on Ethernet (the usual case) and equally inside a
        //VLAN (VLAN-tagged HSR) or a nested HSR tag. This mirrors VLAN_802dot1Q.match exactly.
        if (!this.prevCodecModule) return false
        if (this.prevCodecModule.instance.etherType.getValue() !== UInt16ToHex(0x892f)) return false
        //The 6-octet HSR tag must fit: Path/LSDUsize (2) + SeqNr (2) + carried EtherType (2).
        return this.packet.length - this.startPos >= 6
    }
}
