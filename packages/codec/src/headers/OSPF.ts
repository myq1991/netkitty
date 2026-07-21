import {ProtocolJSONSchema} from '../schema/ProtocolJSONSchema'
import {BaseHeader} from '../abstracts/BaseHeader'
import {StringContentEncodingEnum} from '../lib/StringContentEncodingEnum'
import {BufferToIPv4} from '../helper/BufferToIP'
import {IPv4ToBuffer} from '../helper/IPToBuffer'
import {BufferToHex} from '../helper/BufferToHex'
import {DemuxProducer} from '../types/DemuxProducer'

export class OSPF extends BaseHeader {

    /**
     * Bytes of OSPF the IP layer below says are available.
     * IPv4 carries a total-length field, so the OSPF payload is (total length - IP header length);
     * IPv6 carries the payload length directly (plen). Mirrors the GRE #available() pattern so the
     * body decode can be bounded by the real on-wire length rather than trusting the OSPF length
     * field alone (which a malformed packet may overstate). Returns 0 when neither is present.
     * @private
     */
    #available(): number {
        const prev: any = this.prevCodecModule
        if (!prev) return 0
        const ipv4TotalLength: number = prev.instance.length.getValue(0)
        if (ipv4TotalLength) return ipv4TotalLength - prev.length
        const ipv6PayloadLength: number = prev.instance.plen.getValue(0)
        if (ipv6PayloadLength) return ipv6PayloadLength
        return 0
    }

    /**
     * Header-relative end offset of the OSPF packet body: the OSPF length field, clamped down to the
     * bytes the IP layer actually made available (#available). Never less than the 24-byte common
     * header. Both the Hello neighbour list and the raw-body fallback are bounded by this.
     * @private
     */
    #bodyEnd(): number {
        let end: number = this.instance.packetLength.getValue(0)
        const available: number = this.#available()
        if (available && available < end) end = available
        if (end < 24) end = 24
        return end
    }

    static #schemaCache: ProtocolJSONSchema | undefined

    //Class-cached SCHEMA (field closures are plain functions taking dynamic `this` via .call(this)).
    public get SCHEMA(): ProtocolJSONSchema {
        return (OSPF.#schemaCache ??= OSPF.#buildSchema())
    }

    static #buildSchema(): ProtocolJSONSchema {
        return {
            type: 'object',
            summary: 'OSPF type=${type} rid=${routerId}',
            properties: {
                //==== Common header (24 bytes, RFC 2328 §A.3.1) ====
                version: this.fieldUInt('version', 0, 1, 'Version'),
                type: this.fieldUInt('type', 1, 1, 'Message Type'),
                packetLength: this.fieldUInt('packetLength', 2, 2, 'Packet Length'),
                routerId: {
                    type: 'string',
                    label: 'Source Router ID',
                    minLength: 7,
                    maxLength: 15,
                    contentEncoding: StringContentEncodingEnum.IPv4,
                    decode: function (this: OSPF): void {
                        this.instance.routerId.setValue(BufferToIPv4(this.readBytes(4, 4)))
                    },
                    encode: function (this: OSPF): void {
                        const routerId: string = this.instance.routerId.getValue('0.0.0.0', (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                        this.instance.routerId.setValue(routerId)
                        this.writeBytes(4, IPv4ToBuffer(routerId))
                    }
                },
                areaId: {
                    type: 'string',
                    label: 'Area ID',
                    minLength: 7,
                    maxLength: 15,
                    contentEncoding: StringContentEncodingEnum.IPv4,
                    decode: function (this: OSPF): void {
                        this.instance.areaId.setValue(BufferToIPv4(this.readBytes(8, 4)))
                    },
                    encode: function (this: OSPF): void {
                        const areaId: string = this.instance.areaId.getValue('0.0.0.0', (nodePath: string): void => this.recordError(nodePath, 'Not Found'))
                        this.instance.areaId.setValue(areaId)
                        this.writeBytes(8, IPv4ToBuffer(areaId))
                    }
                },
                //Honored verbatim: the OSPF checksum (ones-complement over the packet excluding the
                //authentication field) is never recomputed, so a captured packet round-trips byte-for-byte.
                checksum: this.fieldUInt('checksum', 12, 2, 'Checksum'),
                auType: this.fieldUInt('auType', 14, 2, 'Auth Type'),
                auth: {
                    type: 'string',
                    label: 'Authentication',
                    minLength: 0,
                    maxLength: 16,
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: OSPF): void {
                        this.instance.auth.setValue(BufferToHex(this.readBytes(16, 8)))
                    },
                    encode: function (this: OSPF): void {
                        const auth: string = this.instance.auth.getValue('0000000000000000')
                        this.instance.auth.setValue(auth)
                        this.writeBytes(16, Buffer.from(auth, 'hex'))
                    }
                },
                //==== Hello body (RFC 2328 §A.3.2), decoded only for type 1 ====
                hello: {
                    type: 'object',
                    label: 'Hello Packet',
                    properties: {
                        networkMask: {
                            type: 'string',
                            label: 'Network Mask',
                            minLength: 7,
                            maxLength: 15,
                            contentEncoding: StringContentEncodingEnum.IPv4,
                            decode: function (this: OSPF): void {
                                const type: number = this.instance.type.getValue(0)
                                if (type !== 1) return
                                this.instance.hello.networkMask.setValue(BufferToIPv4(this.readBytes(24, 4)))
                            },
                            encode: function (this: OSPF): void {
                                const type: number = this.instance.type.getValue(0)
                                if (type !== 1) return
                                const networkMask: string = this.instance.hello.networkMask.getValue('0.0.0.0')
                                this.instance.hello.networkMask.setValue(networkMask)
                                this.writeBytes(24, IPv4ToBuffer(networkMask))
                            }
                        },
                        helloInterval: {
                            type: 'integer',
                            label: 'Hello Interval',
                            minimum: 0,
                            maximum: 65535,
                            decode: function (this: OSPF): void {
                                const type: number = this.instance.type.getValue(0)
                                if (type !== 1) return
                                this.instance.hello.helloInterval.setValue(this.readBits(28, 2, 0, 16))
                            },
                            encode: function (this: OSPF): void {
                                const type: number = this.instance.type.getValue(0)
                                if (type !== 1) return
                                const helloInterval: number = this.instance.hello.helloInterval.getValue(0)
                                this.instance.hello.helloInterval.setValue(helloInterval)
                                this.writeBits(28, 2, 0, 16, helloInterval)
                            }
                        },
                        options: {
                            type: 'integer',
                            label: 'Options',
                            minimum: 0,
                            maximum: 255,
                            decode: function (this: OSPF): void {
                                const type: number = this.instance.type.getValue(0)
                                if (type !== 1) return
                                this.instance.hello.options.setValue(this.readBits(30, 1, 0, 8))
                            },
                            encode: function (this: OSPF): void {
                                const type: number = this.instance.type.getValue(0)
                                if (type !== 1) return
                                const options: number = this.instance.hello.options.getValue(0)
                                this.instance.hello.options.setValue(options)
                                this.writeBits(30, 1, 0, 8, options)
                            }
                        },
                        routerPriority: {
                            type: 'integer',
                            label: 'Router Priority',
                            minimum: 0,
                            maximum: 255,
                            decode: function (this: OSPF): void {
                                const type: number = this.instance.type.getValue(0)
                                if (type !== 1) return
                                this.instance.hello.routerPriority.setValue(this.readBits(31, 1, 0, 8))
                            },
                            encode: function (this: OSPF): void {
                                const type: number = this.instance.type.getValue(0)
                                if (type !== 1) return
                                const routerPriority: number = this.instance.hello.routerPriority.getValue(0)
                                this.instance.hello.routerPriority.setValue(routerPriority)
                                this.writeBits(31, 1, 0, 8, routerPriority)
                            }
                        },
                        routerDeadInterval: {
                            type: 'integer',
                            label: 'Router Dead Interval',
                            minimum: 0,
                            maximum: 4294967295,
                            decode: function (this: OSPF): void {
                                const type: number = this.instance.type.getValue(0)
                                if (type !== 1) return
                                this.instance.hello.routerDeadInterval.setValue(this.readBits(32, 4, 0, 32))
                            },
                            encode: function (this: OSPF): void {
                                const type: number = this.instance.type.getValue(0)
                                if (type !== 1) return
                                const routerDeadInterval: number = this.instance.hello.routerDeadInterval.getValue(0)
                                this.instance.hello.routerDeadInterval.setValue(routerDeadInterval)
                                this.writeBits(32, 4, 0, 32, routerDeadInterval)
                            }
                        },
                        designatedRouter: {
                            type: 'string',
                            label: 'Designated Router',
                            minLength: 7,
                            maxLength: 15,
                            contentEncoding: StringContentEncodingEnum.IPv4,
                            decode: function (this: OSPF): void {
                                const type: number = this.instance.type.getValue(0)
                                if (type !== 1) return
                                this.instance.hello.designatedRouter.setValue(BufferToIPv4(this.readBytes(36, 4)))
                            },
                            encode: function (this: OSPF): void {
                                const type: number = this.instance.type.getValue(0)
                                if (type !== 1) return
                                const designatedRouter: string = this.instance.hello.designatedRouter.getValue('0.0.0.0')
                                this.instance.hello.designatedRouter.setValue(designatedRouter)
                                this.writeBytes(36, IPv4ToBuffer(designatedRouter))
                            }
                        },
                        backupDesignatedRouter: {
                            type: 'string',
                            label: 'Backup Designated Router',
                            minLength: 7,
                            maxLength: 15,
                            contentEncoding: StringContentEncodingEnum.IPv4,
                            decode: function (this: OSPF): void {
                                const type: number = this.instance.type.getValue(0)
                                if (type !== 1) return
                                this.instance.hello.backupDesignatedRouter.setValue(BufferToIPv4(this.readBytes(40, 4)))
                            },
                            encode: function (this: OSPF): void {
                                const type: number = this.instance.type.getValue(0)
                                if (type !== 1) return
                                const backupDesignatedRouter: string = this.instance.hello.backupDesignatedRouter.getValue('0.0.0.0')
                                this.instance.hello.backupDesignatedRouter.setValue(backupDesignatedRouter)
                                this.writeBytes(40, IPv4ToBuffer(backupDesignatedRouter))
                            }
                        },
                        neighbors: {
                            type: 'array',
                            label: 'Active Neighbors',
                            items: {
                                type: 'string',
                                minLength: 7,
                                maxLength: 15,
                                contentEncoding: StringContentEncodingEnum.IPv4
                            },
                            //Neighbour Router IDs run from the end of the fixed Hello fields (offset 44)
                            //to the OSPF packet length, 4 bytes each. Bounded by #bodyEnd so a corrupt
                            //length field can't read past the IP payload.
                            decode: function (this: OSPF): void {
                                const type: number = this.instance.type.getValue(0)
                                if (type !== 1) return
                                const end: number = this.#bodyEnd()
                                const neighbors: string[] = []
                                let offset: number = 44
                                while (offset + 4 <= end) {
                                    neighbors.push(BufferToIPv4(this.readBytes(offset, 4)))
                                    offset += 4
                                }
                                this.instance.hello.neighbors.setValue(neighbors)
                            },
                            encode: function (this: OSPF): void {
                                const type: number = this.instance.type.getValue(0)
                                if (type !== 1) return
                                const neighbors: string[] | undefined = this.instance.hello.neighbors.getValue()
                                if (!neighbors) return
                                let offset: number = 44
                                neighbors.forEach((neighbor: string): void => {
                                    this.writeBytes(offset, IPv4ToBuffer(neighbor))
                                    offset += 4
                                })
                            }
                        }
                    }
                },
                //==== Raw body fallback for types 2-5 (DD / LS Request / LS Update / LS Ack) ====
                //Kept verbatim (like SNMP pduRaw), byte-perfect. Bounded by #bodyEnd.
                rawBody: {
                    type: 'string',
                    label: 'Body',
                    minLength: 0,
                    contentEncoding: StringContentEncodingEnum.HEX,
                    decode: function (this: OSPF): void {
                        const type: number = this.instance.type.getValue(0)
                        if (type === 1) return
                        const end: number = this.#bodyEnd()
                        if (end <= 24) return
                        this.instance.rawBody.setValue(BufferToHex(this.readBytes(24, end - 24)))
                    },
                    encode: function (this: OSPF): void {
                        const type: number = this.instance.type.getValue(0)
                        if (type === 1) return
                        if (this.instance.rawBody.isUndefined()) return
                        this.writeBytes(24, Buffer.from(this.instance.rawBody.getValue(''), 'hex'))
                    }
                }
            }
        }
    }

    public readonly id: string = 'ospf'

    public readonly matchKeys: string[] = ['ipproto:89']

    public readonly name: string = 'Open Shortest Path First'

    public readonly nickname: string = 'OSPF'

    //A leaf header (OSPF LSA bodies are decoded inline / kept as rawBody).
    public readonly demuxProducers: DemuxProducer[] = []

    public match(): boolean {
        if (!this.prevCodecModule) return false
        //OSPF sits directly on IP (protocol 89). Accept the demux value from either the IPv4
        //protocol field or the IPv6 next-header field, and require at least a full 24-byte common
        //header of IP payload to be present.
        const protocol: number = this.prevCodecModule.instance.protocol.getValue(0)
        const nextHeader: number = this.prevCodecModule.instance.nxt.getValue(0)
        if (protocol !== 89 && nextHeader !== 89) return false
        return this.#available() >= 24
    }

}
