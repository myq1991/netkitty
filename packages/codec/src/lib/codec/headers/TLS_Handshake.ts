import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {BaseHeader} from '../abstracts/BaseHeader'
import {
    BufferToInt8,
    BufferToUInt16,
    BufferToUInt32,
    BufferToUInt8
} from '../../helper/BufferToNumber'
import {BufferToHex} from '../../helper/BufferToHex'
import {UInt16ToBuffer, UInt8ToBuffer} from '../../helper/NumberToBuffer'
import {HexToBuffer} from '../../helper/HexToBuffer'

enum TLSver {
    SSL_3_0 = 'SSL3.0',
    TLS_1_0 = 'TLS1.0',
    TLS_1_1 = 'TLS1.1',
    TLS_1_2 = 'TLS1.2',
    TLS_1_3 = 'TLS1.3',
}

enum HandshakeType {
    Handshake_1 = 'HelloRequest',
    Handshake_2 = 'ClientHello',
    Handshake_3 = 'ServerHello',
    Handshake_4 = 'NewSessionTicket',
    Handshake_5 = 'EncryptedExtensions',
    Handshake_6 = 'Certificate',
    Handshake_7 = 'ServerKeyExchange',
    Handshake_8 = 'CertificateRequest',
    Handshake_9 = 'ServerHelloDone',
    Handshake_10 = 'CertificateVerify',
    Handshake_11 = 'ClientKeyExchange',
    Handshake_12 = 'Finished',
}

export class TLS_Handshake extends BaseHeader {

    /**
     * Map a 2-byte TLS version to a friendly string, or its 4-hex form when unknown.
     */
    protected tlsVersionToString(version: number): string {
        switch (version) {
            case 768: return TLSver.SSL_3_0
            case 769: return TLSver.TLS_1_0
            case 770: return TLSver.TLS_1_1
            case 771: return TLSver.TLS_1_2
            case 772: return TLSver.TLS_1_3
            default: return version.toString(16).padStart(4, '0')
        }
    }

    /**
     * Inverse of tlsVersionToString: a friendly string or 4-hex back to 2 bytes.
     */
    protected tlsVersionStringToBuffer(version: string): Buffer {
        switch (version) {
            case TLSver.SSL_3_0: return UInt16ToBuffer(768)
            case TLSver.TLS_1_0: return UInt16ToBuffer(769)
            case TLSver.TLS_1_1: return UInt16ToBuffer(770)
            case TLSver.TLS_1_2: return UInt16ToBuffer(771)
            case TLSver.TLS_1_3: return UInt16ToBuffer(772)
            default: return HexToBuffer(version.padStart(4, '0'))
        }
    }

    /**
     * True when the handshake body could not be structured (unsupported message type or a
     * parse failure) and was preserved as messagedata.raw. Encode then re-emits those bytes
     * verbatim; a structured Hello (messagedata.version set) turns this false.
     */
    protected messagedataRawFallbackActive(): boolean {
        const md: any = this.instance.messagedata
        if (md.raw.isUndefined()) return false
        if (!md.raw.getValue('')) return false
        return md.version.isUndefined()
    }

    /**
     * Structurally decode a ClientHello (handshake type 1) body starting at record offset 9.
     * Throws on any bound overrun / trailing bytes so the caller can fall back to raw.
     */
    protected decodeClientHello(bodyLength: number): void {
        let p: number = 9
        const end: number = 9 + bodyLength
        const need: (n: number) => void = (n: number): void => {
            if (n < 0 || p + n > end) throw new Error('handshake body overrun')
        }
        need(2); const version: number = BufferToUInt16(this.readBytes(p, 2)); p += 2
        need(32); const random: string = BufferToHex(this.readBytes(p, 32)); p += 32
        need(1); const sidLen: number = BufferToUInt8(this.readBytes(p, 1)); p += 1
        need(sidLen); const sessionId: string = BufferToHex(this.readBytes(p, sidLen)); p += sidLen
        need(2); const csLen: number = BufferToUInt16(this.readBytes(p, 2)); p += 2
        need(csLen); const csBuf: Buffer = this.readBytes(p, csLen); p += csLen
        need(1); const cmLen: number = BufferToUInt8(this.readBytes(p, 1)); p += 1
        need(cmLen); const cmBuf: Buffer = this.readBytes(p, cmLen); p += cmLen
        let extensions: any[] | undefined = undefined
        if (p < end) {
            need(2); const extLen: number = BufferToUInt16(this.readBytes(p, 2)); p += 2
            need(extLen); extensions = this.parseTLSExtensions(this.readBytes(p, extLen)); p += extLen
        }
        if (p !== end) throw new Error('trailing bytes in handshake body')
        if (csLen % 2 !== 0) throw new Error('odd cipher-suites length')
        const cipherSuites: string[] = []
        for (let i: number = 0; i < csLen; i += 2) cipherSuites.push(BufferToHex(csBuf.subarray(i, i + 2)))
        const compressionMethods: string[] = []
        for (let i: number = 0; i < cmLen; i++) compressionMethods.push(BufferToHex(cmBuf.subarray(i, i + 1)))
        const md: any = this.instance.messagedata
        md.version.setValue(this.tlsVersionToString(version))
        md.random.setValue(random)
        md.sessionId.setValue(sessionId)
        md.cipherSuites.setValue(cipherSuites)
        md.compressionMethods.setValue(compressionMethods)
        if (extensions !== undefined) md.extensions.setValue(extensions)
    }

    /**
     * Structurally decode a ServerHello (handshake type 2) body starting at record offset 9.
     * Throws on any bound overrun / trailing bytes so the caller can fall back to raw.
     */
    protected decodeServerHello(bodyLength: number): void {
        let p: number = 9
        const end: number = 9 + bodyLength
        const need: (n: number) => void = (n: number): void => {
            if (n < 0 || p + n > end) throw new Error('handshake body overrun')
        }
        need(2); const version: number = BufferToUInt16(this.readBytes(p, 2)); p += 2
        need(32); const random: string = BufferToHex(this.readBytes(p, 32)); p += 32
        need(1); const sidLen: number = BufferToUInt8(this.readBytes(p, 1)); p += 1
        need(sidLen); const sessionId: string = BufferToHex(this.readBytes(p, sidLen)); p += sidLen
        need(2); const cipherSuite: string = BufferToHex(this.readBytes(p, 2)); p += 2
        need(1); const compressionMethod: string = BufferToHex(this.readBytes(p, 1)); p += 1
        let extensions: any[] | undefined = undefined
        if (p < end) {
            need(2); const extLen: number = BufferToUInt16(this.readBytes(p, 2)); p += 2
            need(extLen); extensions = this.parseTLSExtensions(this.readBytes(p, extLen)); p += extLen
        }
        if (p !== end) throw new Error('trailing bytes in handshake body')
        const md: any = this.instance.messagedata
        md.version.setValue(this.tlsVersionToString(version))
        md.random.setValue(random)
        md.sessionId.setValue(sessionId)
        md.cipherSuite.setValue(cipherSuite)
        md.compressionMethod.setValue(compressionMethod)
        if (extensions !== undefined) md.extensions.setValue(extensions)
    }

    /**
     * Friendly name for a 2-byte TLS extension type (IANA registry), or its 4-hex form.
     */
    protected tlsExtensionName(type: string): string {
        const names: {[key: string]: string} = {
            '0000': 'server_name',
            '0001': 'max_fragment_length',
            '0005': 'status_request',
            '000a': 'supported_groups',
            '000b': 'ec_point_formats',
            '000d': 'signature_algorithms',
            '000f': 'heartbeat',
            '0010': 'application_layer_protocol_negotiation',
            '0012': 'signed_certificate_timestamp',
            '0015': 'padding',
            '0016': 'encrypt_then_mac',
            '0017': 'extended_master_secret',
            '001b': 'compress_certificate',
            '0023': 'session_ticket',
            '002a': 'early_data',
            '002b': 'supported_versions',
            '002c': 'cookie',
            '002d': 'psk_key_exchange_modes',
            '0031': 'post_handshake_auth',
            '0032': 'signature_algorithms_cert',
            '0033': 'key_share',
            'ff01': 'renegotiation_info'
        }
        return names[type.toLowerCase()] ? names[type.toLowerCase()] : `unknown_${type}`
    }

    /**
     * Split a TLS extensions block into its individual extensions. Each extension is a
     * type(2) + length(2) + data(length) triple; data is kept as hex (authoritative for
     * re-encode). Throws on any overrun so the caller can fall back to raw.
     */
    protected parseTLSExtensions(buffer: Buffer): any[] {
        const handshakeType: string = this.instance.handshakeType.getValue()
        const extensions: any[] = []
        let q: number = 0
        while (q < buffer.length) {
            if (q + 4 > buffer.length) throw new Error('extension header overrun')
            const type: string = BufferToHex(buffer.subarray(q, q + 2)); q += 2
            const length: number = BufferToUInt16(buffer.subarray(q, q + 2)); q += 2
            if (q + length > buffer.length) throw new Error('extension data overrun')
            const dataBuffer: Buffer = buffer.subarray(q, q + length); q += length
            const name: string = this.tlsExtensionName(type)
            //Decode the inner structure for extensions we have a spec for; on any malformation
            //(or an unknown type) keep the extension data as hex so it still round-trips.
            let structured: any = null
            try {
                structured = this.decodeExtensionData(type, dataBuffer, handshakeType)
            } catch (e) {
                structured = null
            }
            if (structured) extensions.push({type: type, name: name, ...structured})
            else extensions.push({type: type, name: name, data: BufferToHex(dataBuffer)})
        }
        return extensions
    }

    /**
     * Decode a single extension's inner structure by type. Returns the structured fields, or
     * null when the type has no (implemented) structure so the caller keeps it as hex. Throws
     * on any bound violation so the caller falls back to hex for that one extension.
     */
    protected decodeExtensionData(type: string, buffer: Buffer, handshakeType: string): any | null {
        switch (type.toLowerCase()) {
            case '0000': { //server_name
                if (buffer.length === 0) return {serverNames: []} //ServerHello echoes an empty SNI
                const listLength: number = buffer.readUInt16BE(0)
                if (2 + listLength !== buffer.length) throw new Error('server_name list length')
                const serverNames: {nameType: string, hostName: string}[] = []
                let q: number = 2
                while (q < buffer.length) {
                    if (q + 3 > buffer.length) throw new Error('server_name entry overrun')
                    const nameType: number = buffer.readUInt8(q); q += 1
                    const nameLength: number = buffer.readUInt16BE(q); q += 2
                    if (q + nameLength > buffer.length) throw new Error('server_name overrun')
                    serverNames.push({nameType: nameType === 0 ? 'host_name' : `${nameType}`, hostName: buffer.subarray(q, q + nameLength).toString('ascii')}); q += nameLength
                }
                return {serverNames: serverNames}
            }
            case '000a': //supported_groups
                return {groups: this.decodeCodeList16(buffer)}
            case '000d': //signature_algorithms
                return {signatureAlgorithms: this.decodeCodeList16(buffer)}
            case '000b': { //ec_point_formats (1-byte length, 1-byte codes)
                if (buffer.length < 1) throw new Error('ec_point_formats')
                const listLength: number = buffer.readUInt8(0)
                if (1 + listLength !== buffer.length) throw new Error('ec_point_formats length')
                const ecPointFormats: string[] = []
                for (let q: number = 1; q < buffer.length; q++) ecPointFormats.push(BufferToHex(buffer.subarray(q, q + 1)))
                return {ecPointFormats: ecPointFormats}
            }
            case '002d': { //psk_key_exchange_modes (1-byte length, 1-byte modes)
                if (buffer.length < 1) throw new Error('psk_key_exchange_modes')
                const listLength: number = buffer.readUInt8(0)
                if (1 + listLength !== buffer.length) throw new Error('psk_key_exchange_modes length')
                const modes: string[] = []
                for (let q: number = 1; q < buffer.length; q++) modes.push(BufferToHex(buffer.subarray(q, q + 1)))
                return {modes: modes}
            }
            case '0010': { //application_layer_protocol_negotiation (ALPN)
                if (buffer.length < 2) throw new Error('alpn')
                const listLength: number = buffer.readUInt16BE(0)
                if (2 + listLength !== buffer.length) throw new Error('alpn length')
                const protocols: string[] = []
                let q: number = 2
                while (q < buffer.length) {
                    const protocolLength: number = buffer.readUInt8(q); q += 1
                    if (q + protocolLength > buffer.length) throw new Error('alpn protocol overrun')
                    protocols.push(buffer.subarray(q, q + protocolLength).toString('ascii')); q += protocolLength
                }
                return {protocols: protocols}
            }
            case '002b': { //supported_versions (ClientHello: list; ServerHello: single)
                if (handshakeType === HandshakeType.Handshake_3) {
                    if (buffer.length !== 2) throw new Error('supported_versions (server)')
                    return {selectedVersion: this.tlsVersionToString(buffer.readUInt16BE(0))}
                }
                if (buffer.length < 1) throw new Error('supported_versions')
                const listLength: number = buffer.readUInt8(0)
                if (1 + listLength !== buffer.length || listLength % 2 !== 0) throw new Error('supported_versions length')
                const versions: string[] = []
                for (let q: number = 1; q < buffer.length; q += 2) versions.push(this.tlsVersionToString(buffer.readUInt16BE(q)))
                return {versions: versions}
            }
            case '0033': { //key_share (ClientHello: list of entries; ServerHello: single entry)
                if (handshakeType === HandshakeType.Handshake_3) {
                    if (buffer.length < 4) throw new Error('key_share (server)')
                    const keyLength: number = buffer.readUInt16BE(2)
                    if (4 + keyLength !== buffer.length) throw new Error('key_share length (server)')
                    return {keyShare: {group: BufferToHex(buffer.subarray(0, 2)), keyExchange: BufferToHex(buffer.subarray(4))}}
                }
                if (buffer.length < 2) throw new Error('key_share')
                const listLength: number = buffer.readUInt16BE(0)
                if (2 + listLength !== buffer.length) throw new Error('key_share length')
                const keyShares: {group: string, keyExchange: string}[] = []
                let q: number = 2
                while (q < buffer.length) {
                    if (q + 4 > buffer.length) throw new Error('key_share entry overrun')
                    const group: string = BufferToHex(buffer.subarray(q, q + 2)); q += 2
                    const keyLength: number = buffer.readUInt16BE(q); q += 2
                    if (q + keyLength > buffer.length) throw new Error('key_share key overrun')
                    keyShares.push({group: group, keyExchange: BufferToHex(buffer.subarray(q, q + keyLength))}); q += keyLength
                }
                return {keyShares: keyShares}
            }
            default:
                return null //no implemented structure: keep as hex
        }
    }

    /**
     * Decode a 2-byte-length-prefixed list of 2-byte codes into hex strings (used by
     * supported_groups and signature_algorithms).
     */
    protected decodeCodeList16(buffer: Buffer): string[] {
        if (buffer.length < 2) throw new Error('code list')
        const listLength: number = buffer.readUInt16BE(0)
        if (2 + listLength !== buffer.length || listLength % 2 !== 0) throw new Error('code list length')
        const codes: string[] = []
        for (let q: number = 2; q < buffer.length; q += 2) codes.push(BufferToHex(buffer.subarray(q, q + 2)))
        return codes
    }

    /**
     * Rebuild a single extension's data buffer from its structured fields (inverse of
     * decodeExtensionData). Only called for extensions decoded structurally (no `data` hex).
     */
    protected encodeExtensionData(extension: any, handshakeType: string): Buffer {
        switch (extension.type.toLowerCase()) {
            case '0000': { //server_name
                const entries: Buffer = Buffer.concat((extension.serverNames as {nameType: string, hostName: string}[]).map((serverName: {nameType: string, hostName: string}): Buffer => {
                    const host: Buffer = Buffer.from(serverName.hostName, 'ascii')
                    const nameType: number = serverName.nameType === 'host_name' ? 0 : parseInt(serverName.nameType)
                    return Buffer.concat([UInt8ToBuffer(nameType), UInt16ToBuffer(host.length), host])
                }))
                if (entries.length === 0) return Buffer.alloc(0)
                return Buffer.concat([UInt16ToBuffer(entries.length), entries])
            }
            case '000a':
                return this.encodeCodeList16(extension.groups)
            case '000d':
                return this.encodeCodeList16(extension.signatureAlgorithms)
            case '000b': {
                const list: Buffer = Buffer.concat((extension.ecPointFormats as string[]).map((format: string): Buffer => HexToBuffer(format)))
                return Buffer.concat([UInt8ToBuffer(list.length), list])
            }
            case '002d': {
                const list: Buffer = Buffer.concat((extension.modes as string[]).map((mode: string): Buffer => HexToBuffer(mode)))
                return Buffer.concat([UInt8ToBuffer(list.length), list])
            }
            case '0010': {
                const entries: Buffer = Buffer.concat((extension.protocols as string[]).map((protocol: string): Buffer => {
                    const bytes: Buffer = Buffer.from(protocol, 'ascii')
                    return Buffer.concat([UInt8ToBuffer(bytes.length), bytes])
                }))
                return Buffer.concat([UInt16ToBuffer(entries.length), entries])
            }
            case '002b': {
                if (handshakeType === HandshakeType.Handshake_3) return this.tlsVersionStringToBuffer(extension.selectedVersion)
                const list: Buffer = Buffer.concat((extension.versions as string[]).map((version: string): Buffer => this.tlsVersionStringToBuffer(version)))
                return Buffer.concat([UInt8ToBuffer(list.length), list])
            }
            case '0033': {
                if (handshakeType === HandshakeType.Handshake_3) {
                    const key: Buffer = HexToBuffer(extension.keyShare.keyExchange)
                    return Buffer.concat([HexToBuffer(extension.keyShare.group), UInt16ToBuffer(key.length), key])
                }
                const entries: Buffer = Buffer.concat((extension.keyShares as {group: string, keyExchange: string}[]).map((keyShare: {group: string, keyExchange: string}): Buffer => {
                    const key: Buffer = HexToBuffer(keyShare.keyExchange)
                    return Buffer.concat([HexToBuffer(keyShare.group), UInt16ToBuffer(key.length), key])
                }))
                return Buffer.concat([UInt16ToBuffer(entries.length), entries])
            }
            default:
                return Buffer.alloc(0)
        }
    }

    /**
     * Rebuild a 2-byte-length-prefixed list of 2-byte codes (inverse of decodeCodeList16).
     */
    protected encodeCodeList16(codes: string[]): Buffer {
        const list: Buffer = Buffer.concat(codes.map((code: string): Buffer => HexToBuffer(code)))
        return Buffer.concat([UInt16ToBuffer(list.length), list])
    }

    public SCHEMA: ProtocolJSONSchema = {
        type: 'object',
        properties: {
            contentType: {
                type: 'integer',
                label: 'Content Type',
                minimum: 0,
                maximum: 255,
                decode: (): void => {
                    this.instance.contentType.setValue(BufferToInt8(this.readBytes(0, 1)))

                },
                encode: (): void => {

                    const contentType: Buffer = UInt8ToBuffer(this.instance.contentType.getValue(0, (nodePath: string): void => this.recordError(nodePath, 'Not found')))
                    this.writeBytes(0, contentType)

                }
            },
            version: {
                type: 'string',
                label: 'Legacy Version',
                minimum: 0,
                maximum: 65535,
                decode: (): void => {
                    const version: number = BufferToUInt16(this.readBytes(1, 2))
                    switch (version) {
                        case 768: {
                            this.instance.version.setValue(TLSver.SSL_3_0)
                        }
                            break
                        case 769: {
                            this.instance.version.setValue(TLSver.TLS_1_0)
                        }
                            break
                        case 770: {
                            this.instance.version.setValue(TLSver.TLS_1_1)
                        }
                            break
                        case 771: {
                            this.instance.version.setValue(TLSver.TLS_1_2)
                        }
                            break
                        case 772: {
                            this.instance.version.setValue(TLSver.TLS_1_3)
                        }
                            break
                        default: {
                            this.instance.version.setValue('0')
                        }
                    }


                },
                encode: (): void => {
                    const version: string = this.instance.version.getValue('0', (nodePath: string): void => this.recordError(nodePath, 'Not found'))
                    switch (version) {
                        case TLSver.SSL_3_0: {
                            const version: Buffer = UInt16ToBuffer(768)
                            this.writeBytes(1, version)
                        }
                            break
                        case TLSver.TLS_1_0: {
                            const version: Buffer = UInt16ToBuffer(769)
                            this.writeBytes(1, version)
                        }
                            break
                        case TLSver.TLS_1_1: {
                            const version: Buffer = UInt16ToBuffer(770)
                            this.writeBytes(1, version)
                        }
                            break
                        case TLSver.TLS_1_2: {
                            const version: Buffer = UInt16ToBuffer(771)
                            this.writeBytes(1, version)
                        }
                            break
                        case TLSver.TLS_1_3: {
                            const version: Buffer = UInt16ToBuffer(772)
                            this.writeBytes(1, version)
                        }
                            break
                        default: {
                            this.writeBytes(1, UInt16ToBuffer(0))
                        }
                    }
                }
            },
            length: {
                type: 'integer',
                label: 'Length',
                minimum: 0,
                maximum: 65535,
                decode: (): void => {
                    this.instance.length.setValue(BufferToUInt16(this.readBytes(3, 2)))
                },
                encode: (): void => {
                    const length: Buffer = UInt16ToBuffer(this.instance.length.getValue(0, (nodePath: string): void => this.recordError(nodePath, 'Not found')))
                    this.writeBytes(3, length)
                }
            },
            handshakeType: {
                type: 'string',
                label: 'Handshake Type',
                minimum: 0,
                maximum: 65535,
                decode: (): void => {
                    const handshakeType: number = BufferToUInt8(this.readBytes(5, 1))
                    switch (handshakeType) {
                        case 0: {
                            this.instance.handshakeType.setValue(HandshakeType.Handshake_1)
                        }
                            break
                        case 1: {
                            this.instance.handshakeType.setValue(HandshakeType.Handshake_2)
                        }
                            break
                        case 2: {
                            this.instance.handshakeType.setValue(HandshakeType.Handshake_3)
                        }
                            break
                        case 4: {
                            this.instance.handshakeType.setValue(HandshakeType.Handshake_4)
                        }
                            break
                        case 8: {
                            this.instance.handshakeType.setValue(HandshakeType.Handshake_5)
                        }
                            break
                        case 11: {
                            this.instance.handshakeType.setValue(HandshakeType.Handshake_6)
                        }
                            break
                        case 12: {
                            this.instance.handshakeType.setValue(HandshakeType.Handshake_7)
                        }
                            break
                        case 13: {
                            this.instance.handshakeType.setValue(HandshakeType.Handshake_8)
                        }
                            break
                        case 14: {
                            this.instance.handshakeType.setValue(HandshakeType.Handshake_9)
                        }
                            break
                        case 15: {
                            this.instance.handshakeType.setValue(HandshakeType.Handshake_10)
                        }
                            break
                        case 16: {
                            this.instance.handshakeType.setValue(HandshakeType.Handshake_11)
                        }
                            break
                        case 20: {
                            this.instance.handshakeType.setValue(HandshakeType.Handshake_12)
                        }
                            break
                        default: {
                            this.instance.handshakeType.setValue(BufferToUInt8(this.readBytes(5, 1)))
                        }
                    }
                },
                encode: (): void => {
                    const handshakeType: string = this.instance.handshakeType.getValue('0')
                    switch (handshakeType) {
                        case HandshakeType.Handshake_1: {
                            const handshakeType: Buffer = UInt8ToBuffer(0)
                            this.writeBytes(5, handshakeType)
                        }
                            break
                        case HandshakeType.Handshake_2: {
                            const handshakeType: Buffer = UInt8ToBuffer(1)
                            this.writeBytes(5, handshakeType)
                        }
                            break
                        case HandshakeType.Handshake_3: {
                            const handshakeType: Buffer = UInt8ToBuffer(2)
                            this.writeBytes(5, handshakeType)
                        }
                            break
                        case HandshakeType.Handshake_4: {
                            const handshakeType: Buffer = UInt8ToBuffer(4)
                            this.writeBytes(5, handshakeType)
                        }
                            break
                        case HandshakeType.Handshake_5: {
                            const handshakeType: Buffer = UInt8ToBuffer(8)
                            this.writeBytes(5, handshakeType)
                        }
                            break
                        case HandshakeType.Handshake_6: {
                            const handshakeType: Buffer = UInt8ToBuffer(11)
                            this.writeBytes(5, handshakeType)
                        }
                            break
                        case HandshakeType.Handshake_7: {
                            const handshakeType: Buffer = UInt8ToBuffer(12)
                            this.writeBytes(5, handshakeType)
                        }
                            break
                        case HandshakeType.Handshake_8: {
                            const handshakeType: Buffer = UInt8ToBuffer(13)
                            this.writeBytes(5, handshakeType)
                        }
                            break
                        case HandshakeType.Handshake_9: {
                            const handshakeType: Buffer = UInt8ToBuffer(14)
                            this.writeBytes(5, handshakeType)
                        }
                            break
                        case HandshakeType.Handshake_10: {
                            const handshakeType: Buffer = UInt8ToBuffer(15)
                            this.writeBytes(5, handshakeType)
                        }
                            break
                        case HandshakeType.Handshake_11: {
                            const handshakeType: Buffer = UInt8ToBuffer(16)
                            this.writeBytes(5, handshakeType)
                        }
                            break
                        case HandshakeType.Handshake_12: {
                            const handshakeType: Buffer = UInt8ToBuffer(20)
                            this.writeBytes(5, handshakeType)
                        }
                            break
                        default: {
                            const handshakeType1: number = parseInt(handshakeType)
                            this.writeBytes(5, UInt8ToBuffer(handshakeType1))
                        }

                    }
                }
            },
            handshakeLength: {
                type: 'integer',
                label: 'Length',
                minimum: 0,
                maximum: 1118481,
                decode: (): void => {
                    this.instance.handshakeLength.setValue(BufferToUInt32(this.readBytes(6, 3)))
                },
                encode: (): void => {
                    const length1: number = (this.instance.handshakeLength.getValue(0, (nodePath: string): void => this.recordError(nodePath, 'Not found')))
                    const length2: string = length1.toString(16).padStart(6, '0')
                    const length3: Buffer = HexToBuffer(length2)
                    this.writeBytes(6, length3)
                }
            },
            messagedata: {
                type: 'object',
                label: 'Message Data',
                properties: {
                    version: {type: 'string', label: 'Version'},
                    random: {type: 'string', contentEncoding: 'hex', label: 'Random'},
                    sessionId: {type: 'string', contentEncoding: 'hex', label: 'Session ID'},
                    cipherSuites: {type: 'array', label: 'Cipher Suites', items: {type: 'string'}},
                    cipherSuite: {type: 'string', label: 'Cipher Suite'},
                    compressionMethods: {type: 'array', label: 'Compression Methods', items: {type: 'string'}},
                    compressionMethod: {type: 'string', label: 'Compression Method'},
                    extensions: {
                        type: 'array',
                        label: 'Extensions',
                        items: {
                            type: 'object',
                            properties: {
                                type: {type: 'string', label: 'Type'},
                                name: {type: 'string', label: 'Name'},
                                //Present only for extensions we cannot structure (unknown type or
                                //malformed): the raw extension data, kept as hex so it round-trips.
                                data: {type: 'string', contentEncoding: 'hex', label: 'Data'},
                                //Structured forms (present per extension type instead of `data`).
                                serverNames: {
                                    type: 'array', label: 'Server Names',
                                    items: {type: 'object', properties: {nameType: {type: 'string', label: 'Name Type'}, hostName: {type: 'string', label: 'Host Name'}}}
                                },
                                groups: {type: 'array', label: 'Supported Groups', items: {type: 'string'}},
                                signatureAlgorithms: {type: 'array', label: 'Signature Algorithms', items: {type: 'string'}},
                                ecPointFormats: {type: 'array', label: 'EC Point Formats', items: {type: 'string'}},
                                modes: {type: 'array', label: 'PSK Key Exchange Modes', items: {type: 'string'}},
                                protocols: {type: 'array', label: 'ALPN Protocols', items: {type: 'string'}},
                                versions: {type: 'array', label: 'Supported Versions', items: {type: 'string'}},
                                selectedVersion: {type: 'string', label: 'Selected Version'},
                                keyShares: {
                                    type: 'array', label: 'Key Shares',
                                    items: {type: 'object', properties: {group: {type: 'string', label: 'Group'}, keyExchange: {type: 'string', contentEncoding: 'hex', label: 'Key Exchange'}}}
                                },
                                keyShare: {
                                    type: 'object', label: 'Key Share',
                                    properties: {group: {type: 'string', label: 'Group'}, keyExchange: {type: 'string', contentEncoding: 'hex', label: 'Key Exchange'}}
                                }
                            }
                        }
                    },
                    raw: {type: 'string', contentEncoding: 'hex', label: 'Unparsed Body'}
                },
                decode: (): void => {
                    const handshakeLength: number = (this.instance.handshakeLength.getValue(0, (nodePath: string): void => this.recordError(nodePath, 'Not found')))
                    //handshakeLength describes the whole (possibly reassembled) message, which may
                    //span multiple TLS records. The body carried by THIS record is bounded by the
                    //record-layer length minus the 4-byte handshake header (type + 3-byte length);
                    //reading handshakeLength bytes would cross the record boundary and swallow the
                    //following record.
                    const recordLength: number = this.instance.length.getValue(0)
                    const bodyLength: number = recordLength > 4 ? Math.min(handshakeLength, recordLength - 4) : handshakeLength
                    this.instance.messagedata.setValue({})
                    const handshakeType: string = this.instance.handshakeType.getValue()
                    try {
                        if (handshakeType === HandshakeType.Handshake_2) this.decodeClientHello(bodyLength)
                        else if (handshakeType === HandshakeType.Handshake_3) this.decodeServerHello(bodyLength)
                        else throw new Error('unstructured')
                    } catch (e) {
                        //Unsupported message type or a malformed Hello: keep the whole body as a
                        //visible raw field so the analyst sees it and encode reproduces it verbatim.
                        this.instance.messagedata.raw.setValue(BufferToHex(this.readBytes(9, bodyLength)))
                        if ((e as Error).message !== 'unstructured') {
                            this.recordError(this.instance.messagedata.getPath(), `Failed to parse handshake body: ${(e as Error).message}`)
                        }
                    }
                },
                encode: (): void => {
                    const md: any = this.instance.messagedata
                    if (this.messagedataRawFallbackActive()) {
                        this.writeBytes(9, HexToBuffer(md.raw.getValue().toString()))
                        return
                    }
                    const handshakeType: string = this.instance.handshakeType.getValue()
                    const parts: Buffer[] = []
                    parts.push(this.tlsVersionStringToBuffer(md.version.getValue('0', (nodePath: string): void => this.recordError(nodePath, 'Not found'))))
                    parts.push(HexToBuffer(md.random.getValue('')))
                    const sessionId: Buffer = HexToBuffer(md.sessionId.getValue(''))
                    parts.push(UInt8ToBuffer(sessionId.length), sessionId)
                    if (handshakeType === HandshakeType.Handshake_3) {
                        parts.push(HexToBuffer(md.cipherSuite.getValue('')))
                        parts.push(HexToBuffer(md.compressionMethod.getValue('')))
                    } else {
                        const cipherSuites: Buffer = Buffer.concat((md.cipherSuites.getValue([]) as string[]).map((code: string): Buffer => HexToBuffer(code)))
                        parts.push(UInt16ToBuffer(cipherSuites.length), cipherSuites)
                        const compressionMethods: Buffer = Buffer.concat((md.compressionMethods.getValue([]) as string[]).map((code: string): Buffer => HexToBuffer(code)))
                        parts.push(UInt8ToBuffer(compressionMethods.length), compressionMethods)
                    }
                    if (!md.extensions.isUndefined()) {
                        const extensionList: any[] = md.extensions.getValue([])
                        const extensions: Buffer = Buffer.concat(extensionList.map((extension: any): Buffer => {
                            //Structurally decoded extensions carry their specific fields (no `data`);
                            //rebuild those from the fields. Hex-preserved extensions carry `data`.
                            const data: Buffer = extension.data !== undefined ? HexToBuffer(extension.data) : this.encodeExtensionData(extension, handshakeType)
                            return Buffer.concat([HexToBuffer(extension.type), UInt16ToBuffer(data.length), data])
                        }))
                        parts.push(UInt16ToBuffer(extensions.length), extensions)
                    }
                    this.writeBytes(9, Buffer.concat(parts))
                }
            }


        }
    }
    public id: string = 'tls-handshake'
    //Fast-path bucket on the well-known HTTPS port; heuristicFallback keeps it matched on any other
    //port by its record content (0x16 + version), so TLS on e.g. tcp:8443 still decodes.
    public readonly matchKeys: string[] = ['tcpport:443']
    public readonly heuristicFallback: boolean = true
    public name: string = 'Transport Layer Security(Handshake Protocol)'
    public nickname: string = 'TLS-Handshake'

    public match(): boolean {
        if (!this.prevCodecModule) return false
        if (BufferToHex(this.readBytes(0, 1)) != '16') return false
        const version: number = BufferToUInt16(this.readBytes(1, 2))
        const validVersions: number[] = [768, 769, 770, 771, 772]
        return validVersions.includes(version)
    }

}