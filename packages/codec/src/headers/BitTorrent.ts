import {BaseHeader} from '../abstracts/BaseHeader'
import {ProtocolJSONSchema} from '../schema/ProtocolJSONSchema'
import {DemuxProducer} from '../types/DemuxProducer'
import {BufferToHex} from '../helper/BufferToHex'

/**
 * BitTorrent — peer wire protocol (BEP 3) handshake, carried over TCP on dynamic/ephemeral ports.
 * A peer connection opens with a fixed 68-byte handshake: a 1-byte pstrlen (0x13 = 19), the 19-byte
 * protocol string "BitTorrent protocol" (pstr), 8 reserved bytes (extension bit-flags — DHT, Fast,
 * Extension Protocol, etc.), the 20-byte SHA-1 info_hash of the torrent, and the 20-byte peer_id.
 *
 * This codec handles ONLY the handshake — its 0x13 + "BitTorrent protocol" prefix is an extremely
 * distinctive 20-byte content signature, so the header is selected by heuristicFallback (no fixed
 * port). The subsequent length-prefixed peer messages (<length(4)><type(1)><payload>) carry no such
 * signature and are intentionally NOT claimed here: after the 68-byte handshake is consumed, any
 * trailing bytes (a pipelined first peer message, etc.) are left to the codec's recursion / RawData.
 * Every field is kept verbatim (reserved / info_hash / peer_id are opaque hex), nothing is recomputed
 * on encode, so a well-formed handshake round-trips byte-for-byte.
 */
export class BitTorrent extends BaseHeader {

    static #schemaCache: ProtocolJSONSchema | undefined

    public get SCHEMA(): ProtocolJSONSchema {
        return (BitTorrent.#schemaCache ??= BitTorrent.#buildSchema())
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'BitTorrent handshake infoHash=${infoHash}',
            properties: {
                //Protocol string length — always 0x13 (19) for the BEP 3 handshake. Kept as a plain uint8
                //(a crafted handshake may lie); the signature match already guards real traffic.
                pstrlen: this.fieldUInt('pstrlen', 0, 1, 'Protocol String Length'),
                //The 19-byte protocol identifier "BitTorrent protocol". Kept verbatim as hex so any
                //byte edit round-trips; the human-readable form is UI enrichment for later.
                pstr: this.fieldHex('pstr', 1, 19, 'Protocol String'),
                //8 reserved bytes carrying extension bit-flags (BEP 4/5/6/10: DHT, Fast, Extension
                //Protocol). Opaque here and re-emitted verbatim.
                reserved: this.fieldHex('reserved', 20, 8, 'Reserved'),
                //20-byte SHA-1 hash of the torrent's info dictionary — identifies the swarm. Verbatim hex.
                infoHash: this.fieldHex('infoHash', 28, 20, 'Info Hash'),
                //20-byte peer identifier chosen by the connecting client (often an ASCII client tag +
                //random suffix). Verbatim hex.
                peerId: this.fieldHex('peerId', 48, 20, 'Peer ID')
            }
        }
    }

    public readonly id: string = 'bittorrent'

    public readonly name: string = 'BitTorrent Peer Wire Protocol'

    public readonly nickname: string = 'BitTorrent'

    //No fixed port — BitTorrent peers connect on dynamic/ephemeral ports. Selection is by the
    //content signature (0x13 + "BitTorrent protocol") via heuristicFallback + match().
    public readonly matchKeys: string[] = []

    public readonly heuristicFallback: boolean = true

    public match(): boolean {
        //Rides on TCP. Require the full 68-byte handshake present so a truncated prefix is not claimed
        //(it falls through to raw and merely survives). The 0x13 pstrlen + the exact 19-byte
        //"BitTorrent protocol" string is a distinctive content signature safe to match on any port.
        if (!this.prevCodecModule || this.prevCodecModule.id !== 'tcp') return false
        if (this.packet.length - this.startPos < 68) return false
        if (this.readBytes(0, 1, true)[0] !== 0x13) return false
        return BufferToHex(this.readBytes(1, 19, true)) === '426974546f7272656e742070726f746f636f6c'
    }

    //A leaf header — only the handshake is decoded; subsequent peer messages are left to raw.
    public readonly demuxProducers: DemuxProducer[] = []

}
