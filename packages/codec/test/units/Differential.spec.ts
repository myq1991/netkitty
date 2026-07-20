import {test} from 'node:test'
import assert from 'node:assert'
import {tsharkAvailable, tsharkLayers, TsharkLayers} from '../lib/Tshark'
import {AllPacketFixtureNames, LoadPacket} from '../lib/Fixtures'
import {Decode} from '../lib/RoundTrip'
import {CodecDecodeResult} from '../../src/lib/codec/types/CodecDecodeResult'

/**
 * Differential oracle: netkitty's decoded value for a field must equal Wireshark/tshark's own
 * dissection of the same bytes. This is the check that catches SYMMETRIC-wrong decodes — a field
 * read with a consistent-but-wrong interpretation round-trips perfectly yet is wrong; only an
 * independent ground truth exposes it. Mapping cost is O(protocol), not O(fixture).
 */

type ValueKind = 'mac' | 'hexcode' | 'int' | 'str'
type FieldMap = {nk: string, ts: string, kind: ValueKind}
type LayerMap = {tsLayer: string, fields: FieldMap[]}

// netkitty layer id → { tshark layer name, per-field mapping }. Only stable, authoritative fields
// are mapped (tshark shows relative TCP seq/ack and scaled windows, and compresses IPv6 addresses,
// so those are intentionally excluded).
const MAPPINGS: {[layerId: string]: LayerMap} = {
    eth: {tsLayer: 'eth', fields: [
        {nk: 'dmac', ts: 'eth.dst', kind: 'mac'},
        {nk: 'smac', ts: 'eth.src', kind: 'mac'},
        {nk: 'etherType', ts: 'eth.type', kind: 'hexcode'}
    ]},
    ipv4: {tsLayer: 'ip', fields: [
        {nk: 'version', ts: 'ip.version', kind: 'int'},
        {nk: 'hdrLen', ts: 'ip.hdr_len', kind: 'int'},
        {nk: 'length', ts: 'ip.len', kind: 'int'},
        {nk: 'ttl', ts: 'ip.ttl', kind: 'int'},
        {nk: 'protocol', ts: 'ip.proto', kind: 'int'},
        {nk: 'fragOffset', ts: 'ip.frag_offset', kind: 'int'},
        {nk: 'sip', ts: 'ip.src', kind: 'str'},
        {nk: 'dip', ts: 'ip.dst', kind: 'str'}
    ]},
    ipv6: {tsLayer: 'ipv6', fields: [
        {nk: 'version', ts: 'ipv6.version', kind: 'int'},
        {nk: 'plen', ts: 'ipv6.plen', kind: 'int'},
        {nk: 'nxt', ts: 'ipv6.nxt', kind: 'int'},
        {nk: 'hllm', ts: 'ipv6.hlim', kind: 'int'}
    ]},
    tcp: {tsLayer: 'tcp', fields: [
        {nk: 'srcport', ts: 'tcp.srcport', kind: 'int'},
        {nk: 'dstport', ts: 'tcp.dstport', kind: 'int'},
        {nk: 'window', ts: 'tcp.window_size_value', kind: 'int'}
    ]},
    udp: {tsLayer: 'udp', fields: [
        {nk: 'srcport', ts: 'udp.srcport', kind: 'int'},
        {nk: 'dstport', ts: 'udp.dstport', kind: 'int'},
        {nk: 'length', ts: 'udp.length', kind: 'int'}
    ]},
    arp: {tsLayer: 'arp', fields: [
        {nk: 'hardware.type', ts: 'arp.hw.type', kind: 'int'},
        {nk: 'hardware.size', ts: 'arp.hw.size', kind: 'int'},
        {nk: 'protocol.type', ts: 'arp.proto.type', kind: 'hexcode'},
        {nk: 'protocol.size', ts: 'arp.proto.size', kind: 'int'},
        {nk: 'opcode', ts: 'arp.opcode', kind: 'int'},
        {nk: 'sender.mac', ts: 'arp.src.hw_mac', kind: 'mac'},
        {nk: 'sender.ipv4', ts: 'arp.src.proto_ipv4', kind: 'str'},
        {nk: 'target.mac', ts: 'arp.dst.hw_mac', kind: 'mac'},
        {nk: 'target.ipv4', ts: 'arp.dst.proto_ipv4', kind: 'str'}
    ]},
    icmp: {tsLayer: 'icmp', fields: [
        {nk: 'type', ts: 'icmp.type', kind: 'int'},
        {nk: 'code', ts: 'icmp.code', kind: 'int'}
    ]},
    icmpv6: {tsLayer: 'icmpv6', fields: [
        {nk: 'type', ts: 'icmpv6.type', kind: 'int'},
        {nk: 'code', ts: 'icmpv6.code', kind: 'int'}
    ]},
    ntp: {tsLayer: 'ntp', fields: [
        // li/vn/mode live under tshark's ntp.flags_tree; getTsharkField finds them. precision is signed
        // — a strong symmetric-wrong catch (unsigned 0xe7=231 would fail against tshark's -25).
        {nk: 'li', ts: 'ntp.flags.li', kind: 'int'},
        {nk: 'vn', ts: 'ntp.flags.vn', kind: 'int'},
        {nk: 'mode', ts: 'ntp.flags.mode', kind: 'int'},
        {nk: 'stratum', ts: 'ntp.stratum', kind: 'int'},
        {nk: 'poll', ts: 'ntp.ppoll', kind: 'int'},
        {nk: 'precision', ts: 'ntp.precision', kind: 'int'}
    ]},
    stun: {tsLayer: 'stun', fields: [
        // tshark shows stun.type as '0x0101'; Number('0x0101')===257 matches our integer messageType,
        // so kind:'int' (not hexcode, whose string-strip would give '257' vs '0101'). Message class
        // (request 0x0001 vs response 0x0101) is the strong differential catch here.
        {nk: 'messageType', ts: 'stun.type', kind: 'int'},
        {nk: 'messageLength', ts: 'stun.length', kind: 'int'}
    ]},
    dhcp: {tsLayer: 'dhcp', fields: [
        // dhcp.type is the BOOTP op (1 request / 2 reply); the DHCP message type (DISCOVER/ACK) is
        // option 53, not mapped here. xid/flags are shown as 0x-hex — Number() parses those, so kind:'int'.
        {nk: 'op', ts: 'dhcp.type', kind: 'int'},
        {nk: 'htype', ts: 'dhcp.hw.type', kind: 'int'},
        {nk: 'hlen', ts: 'dhcp.hw.len', kind: 'int'},
        {nk: 'hops', ts: 'dhcp.hops', kind: 'int'},
        {nk: 'xid', ts: 'dhcp.id', kind: 'int'},
        {nk: 'secs', ts: 'dhcp.secs', kind: 'int'},
        {nk: 'flags', ts: 'dhcp.flags', kind: 'int'},
        {nk: 'ciaddr', ts: 'dhcp.ip.client', kind: 'str'},
        {nk: 'yiaddr', ts: 'dhcp.ip.your', kind: 'str'},
        {nk: 'siaddr', ts: 'dhcp.ip.server', kind: 'str'},
        {nk: 'giaddr', ts: 'dhcp.ip.relay', kind: 'str'}
    ]},
    dns: {tsLayer: 'dns', fields: [
        {nk: 'id', ts: 'dns.id', kind: 'int'},
        // flag bits (tshark shows them as 0/1 under dns.flags_tree); our qr is a boolean → Number() → 0/1.
        {nk: 'flags.qr', ts: 'dns.flags.response', kind: 'int'},
        {nk: 'flags.opcode', ts: 'dns.flags.opcode', kind: 'int'},
        {nk: 'flags.rcode', ts: 'dns.flags.rcode', kind: 'int'},
        {nk: 'qdcount', ts: 'dns.count.queries', kind: 'int'},
        {nk: 'ancount', ts: 'dns.count.answers', kind: 'int'},
        // The resolved names. answers[0].name comes from a COMPRESSION POINTER (0xc00c) — matching
        // tshark's resolved 'test.local' proves the pointer is followed correctly, the key DNS check.
        {nk: 'questions.0.name.value', ts: 'dns.qry.name', kind: 'str'},
        {nk: 'answers.0.name.value', ts: 'dns.resp.name', kind: 'str'}
    ]},
    snmp: {tsLayer: 'snmp', fields: [
        {nk: 'version', ts: 'snmp.version', kind: 'int'},
        {nk: 'community', ts: 'snmp.community', kind: 'str'},
        {nk: 'requestId', ts: 'snmp.request_id', kind: 'int'},
        {nk: 'errorStatus', ts: 'snmp.error_status', kind: 'int'},
        {nk: 'errorIndex', ts: 'snmp.error_index', kind: 'int'},
        // The decoded object identifier — verifies the BER OID base-128 decode matches tshark.
        {nk: 'variableBindings.0.oid', ts: 'snmp.name', kind: 'str'}
    ]},
    // mDNS reuses the DNS wire format (and tshark's dns.* fields under an 'mdns' layer). Same mapping —
    // the answer name in the response comes from a compression pointer, verified against tshark.
    mdns: {tsLayer: 'mdns', fields: [
        {nk: 'qdcount', ts: 'dns.count.queries', kind: 'int'},
        {nk: 'ancount', ts: 'dns.count.answers', kind: 'int'},
        {nk: 'flags.qr', ts: 'dns.flags.response', kind: 'int'},
        {nk: 'questions.0.name.value', ts: 'dns.qry.name', kind: 'str'},
        {nk: 'answers.0.name.value', ts: 'dns.resp.name', kind: 'str'}
    ]},
    tftp: {tsLayer: 'tftp', fields: [
        {nk: 'opcode', ts: 'tftp.opcode', kind: 'int'},
        {nk: 'filename', ts: 'tftp.source_file', kind: 'str'},
        {nk: 'mode', ts: 'tftp.type', kind: 'str'}
    ]},
    // LLMNR reuses the DNS wire format (tshark's dns.* fields under an 'llmnr' layer), like mDNS.
    llmnr: {tsLayer: 'llmnr', fields: [
        {nk: 'id', ts: 'dns.id', kind: 'int'},
        {nk: 'qdcount', ts: 'dns.count.queries', kind: 'int'},
        {nk: 'flags.qr', ts: 'dns.flags.response', kind: 'int'},
        {nk: 'questions.0.name.value', ts: 'dns.qry.name', kind: 'str'}
    ]},
    nbns: {tsLayer: 'nbns', fields: [
        {nk: 'id', ts: 'nbns.id', kind: 'int'},
        {nk: 'qdcount', ts: 'nbns.count.queries', kind: 'int'},
        {nk: 'flags.qr', ts: 'nbns.flags.response', kind: 'int'},
        // The first-level-decoded NetBIOS name (e.g. "WORKGROUP<00>") — verifies our decode matches tshark.
        {nk: 'questions.0.name.value', ts: 'nbns.name', kind: 'str'}
    ]},
    // Syslog: verify the PRI split into facility/severity matches tshark. (The message body granularity
    // differs — we keep the whole body, tshark extracts just the MSG — so message is not mapped.)
    syslog: {tsLayer: 'syslog', fields: [
        {nk: 'facility', ts: 'syslog.facility', kind: 'int'},
        {nk: 'severity', ts: 'syslog.level', kind: 'int'}
    ]},
    radius: {tsLayer: 'radius', fields: [
        {nk: 'code', ts: 'radius.code', kind: 'int'},
        {nk: 'identifier', ts: 'radius.id', kind: 'int'},
        {nk: 'length', ts: 'radius.length', kind: 'int'}
    ]},
    // VXLAN: verify the 24-bit VNI. (tshark's vxlan.flags is a 16-bit view vs our 8-bit flags byte, so
    // it is not mapped.) The inner eth/ipv6/icmpv6 layers are compared via their own mappings — the
    // outer+inner 'eth' pair appears twice in frame.protocols and is skipped by the duplicate-layer guard.
    vxlan: {tsLayer: 'vxlan', fields: [
        {nk: 'vni', ts: 'vxlan.vni', kind: 'int'}
    ]},
    // GTP-U: verify TEID + message type. The inner IP is decoded recursively; the inner icmp/… layers
    // are compared via their own mappings (the outer+inner 'ip' pair is skipped by the duplicate guard).
    gtp: {tsLayer: 'gtp', fields: [
        {nk: 'teid', ts: 'gtp.teid', kind: 'hexcode'},
        {nk: 'msgType', ts: 'gtp.message', kind: 'int'}
    ]},
    // RMCP header core. tshark renders these as 0x-hex; kind 'int' compares numerically
    // (Number('0x06')===6). rmcp.class is nested under tshark's "Type: …, Class: …" group but
    // getTsharkField's DFS reaches it. The ASF sub-message (asf.iana/type/…) is a SEPARATE tshark
    // layer with no netkitty layer of its own to key a mapping on, so it is verified byte-for-byte by
    // the round-trip + golden instead.
    rmcp: {tsLayer: 'rmcp', fields: [
        {nk: 'version', ts: 'rmcp.version', kind: 'int'},
        {nk: 'sequence', ts: 'rmcp.sequence', kind: 'int'},
        {nk: 'messageClass.class', ts: 'rmcp.class', kind: 'int'}
    ]},
    // TACACS+ (RFC 8907, tcp:49). type/seq/session/length verify the header; the version nibbles are
    // rendered byte-positioned by tshark (majvers=0xc0) so they are covered by round-trip + golden, as is
    // the encrypted body.
    tacacs: {tsLayer: 'tacplus', fields: [
        {nk: 'type', ts: 'tacplus.type', kind: 'int'},
        {nk: 'seqNo', ts: 'tacplus.seqno', kind: 'int'},
        {nk: 'flags', ts: 'tacplus.flags', kind: 'int'},
        {nk: 'sessionId', ts: 'tacplus.session_id', kind: 'int'},
        {nk: 'length', ts: 'tacplus.packet_len', kind: 'int'}
    ]},
    // SIP (RFC 3261, tcp/udp:5060). The parsed request-line method + URI (display-only; the whole message
    // is kept verbatim for byte-perfect). tshark exposes sip.Method / sip.r-uri as clean tokens.
    sip: {tsLayer: 'sip', fields: [
        {nk: 'method', ts: 'sip.Method', kind: 'str'},
        {nk: 'requestUri', ts: 'sip.r-uri', kind: 'str'}
    ]},
    // PROFINET-RT (IEC 61158, ethertype 0x8892). tshark names the layer 'pn_rt'. frameId verifies the
    // 2-byte Frame ID (tshark shows it as a decimal). The IO data + APDU-Status (deferred structuring) are
    // kept verbatim and verified by round-trip + golden.
    pnio: {tsLayer: 'pn_rt', fields: [
        {nk: 'frameId', ts: 'pn_rt.frame_id', kind: 'int'}
    ]},
    // EtherCAT (IEC 61158 Type 12, ethertype 0x88a4). tshark names the frame-header layer 'ecatf' and
    // renders the fields as 0x-hex; kind 'int' compares numerically (Number('0x0010')===16). The little-
    // endian header split (11-bit length / 1-bit reserved / 4-bit type) is verified against tshark here;
    // the datagram chain (deferred structuring) is verified byte-for-byte by round-trip + golden.
    ecat: {tsLayer: 'ecatf', fields: [
        {nk: 'length', ts: 'ecatf.length', kind: 'int'},
        {nk: 'reserved', ts: 'ecatf.reserved', kind: 'int'},
        {nk: 'type', ts: 'ecatf.type', kind: 'int'}
    ]},
    // HTTP/1.x (RFC 7230, tcp:80). The parsed request-line method/URI/version (display-only; the whole
    // message is kept verbatim for byte-perfect). tshark nests these under the request-line group, which
    // getTsharkField's DFS reaches.
    http: {tsLayer: 'http', fields: [
        {nk: 'method', ts: 'http.request.method', kind: 'str'},
        {nk: 'requestUri', ts: 'http.request.uri', kind: 'str'},
        {nk: 'version', ts: 'http.request.version', kind: 'str'}
    ]},
    // FTP control channel (RFC 959, tcp:21). The parsed command + argument (display-only; the whole line
    // is kept verbatim for byte-perfect). tshark nests these under the request-line group (DFS reaches them).
    ftp: {tsLayer: 'ftp', fields: [
        {nk: 'command', ts: 'ftp.request.command', kind: 'str'},
        {nk: 'argument', ts: 'ftp.request.arg', kind: 'str'}
    ]},
    // RTSP (RFC 2326, tcp:554). The parsed method/URI + CSeq (display-only; whole message kept verbatim).
    // tshark nests method/url under rtsp.request_tree (DFS reaches them); rtsp.cseq is a top-level int.
    rtsp: {tsLayer: 'rtsp', fields: [
        {nk: 'method', ts: 'rtsp.method', kind: 'str'},
        {nk: 'requestUri', ts: 'rtsp.url', kind: 'str'},
        {nk: 'cseq', ts: 'rtsp.cseq', kind: 'int'}
    ]},
    // TPKT (RFC 1006, tcp:102) — the ISO-transport framing over TCP. version/reserved/length verify the
    // 4-byte header.
    tpkt: {tsLayer: 'tpkt', fields: [
        {nk: 'version', ts: 'tpkt.version', kind: 'int'},
        {nk: 'reserved', ts: 'tpkt.reserved', kind: 'int'},
        {nk: 'length', ts: 'tpkt.length', kind: 'int'}
    ]},
    // COTP (ISO 8073, child of TPKT). li + the DT EOT/TPDU-NR verify the header. pduType is deliberately
    // NOT mapped: netkitty stores the full PDU-type octet (DT=0xF0=240) whereas tshark's cotp.type is the
    // high nibble (0x0f=15); the type is covered by round-trip + golden. eot is a boolean → Number()→0/1.
    cotp: {tsLayer: 'cotp', fields: [
        {nk: 'li', ts: 'cotp.li', kind: 'int'},
        {nk: 'eot', ts: 'cotp.eot', kind: 'int'},
        {nk: 'tpduNr', ts: 'cotp.tpdu-number', kind: 'int'}
    ]},
    // HSR (IEC 62439-3, ethertype 0x892f). The 6-byte tag: path (4b) + LSDU size (12b) + sequence + the
    // carried EtherType. tshark further splits path into netid/laneid but also exposes the whole nibble as
    // hsr.path. hsr.type is the carried EtherType (0x-hex → hexcode strips 0x).
    hsr: {tsLayer: 'hsr', fields: [
        {nk: 'path', ts: 'hsr.path', kind: 'int'},
        {nk: 'lsduSize', ts: 'hsr.lsdu_size', kind: 'int'},
        {nk: 'seqNr', ts: 'hsr.sequence_nr', kind: 'int'},
        {nk: 'etherType', ts: 'hsr.type', kind: 'hexcode'}
    ]},
    // SMTP (RFC 5321, tcp:25). The parsed command + parameter (display-only; whole message kept verbatim).
    // tshark nests them under smtp.command_line_tree (DFS reaches them).
    smtp: {tsLayer: 'smtp', fields: [
        {nk: 'command', ts: 'smtp.req.command', kind: 'str'},
        {nk: 'argument', ts: 'smtp.req.parameter', kind: 'str'}
    ]},
    // POP3 (RFC 1939, tcp:110). tshark names the layer 'pop'. command + parameter (display-only) nested
    // under pop.request_tree.
    pop3: {tsLayer: 'pop', fields: [
        {nk: 'command', ts: 'pop.request.command', kind: 'str'},
        {nk: 'argument', ts: 'pop.request.parameter', kind: 'str'}
    ]},
    // IMAP (RFC 3501, tcp:143). The parsed tag + command (display-only; whole message kept verbatim).
    // tshark nests them under imap.line_tree (DFS reaches imap.request_tag / imap.request.command).
    imap: {tsLayer: 'imap', fields: [
        {nk: 'tag', ts: 'imap.request_tag', kind: 'str'},
        {nk: 'command', ts: 'imap.request.command', kind: 'str'}
    ]},
    // IRC (RFC 2812, tcp:6667). The parsed command (display-only). tshark nests it under irc.request_tree
    // (DFS reaches irc.request.command). Params are split into an array by tshark (DFS-unreliable), so
    // only the command is mapped; the rest is covered by round-trip + golden.
    irc: {tsLayer: 'irc', fields: [
        {nk: 'command', ts: 'irc.request.command', kind: 'str'}
    ]},
    // NNTP (RFC 3977, tcp:119): tshark marks nntp.request but does NOT structure the request command line
    // into fields, so there is no authoritative field to map — the command/argument parse is verified by
    // round-trip + golden instead (like LLDP's opaque TLVs).
    // OPC UA Connection Protocol (tcp:4840). tshark names the layer 'opcua'. The 8-byte transport header:
    // message type (HEL/ACK/MSG/…) + chunk + size. The message body is verified by round-trip + golden.
    opcua: {tsLayer: 'opcua', fields: [
        {nk: 'messageType', ts: 'opcua.transport.type', kind: 'str'},
        {nk: 'chunk', ts: 'opcua.transport.chunk', kind: 'str'},
        {nk: 'messageSize', ts: 'opcua.transport.size', kind: 'int'}
    ]},
    // Redis RESP (tcp:6379): tshark names the layer 'resp' and nests repeated resp.bulk_string keys, which
    // collapse last-wins under -T json — so the command verb (first bulk string) is not reliably mappable.
    // The respType/command parse is verified by round-trip + golden instead (like NNTP/LLDP).
    // LLDP (IEEE 802.1AB, ethertype 0x88cc): the TLV values are kept as opaque hex, so tshark's decoded
    // per-TLV scalars (lldp.time_to_live etc.) do not map to a single field — verified by round-trip + golden.
    // MQTT (OASIS 3.1.1/5.0, tcp:1883). Message type (tshark nests it under mqtt.hdrflags_tree) + the
    // varint Remaining Length. The variable header/payload is verified by round-trip + golden.
    mqtt: {tsLayer: 'mqtt', fields: [
        {nk: 'messageType', ts: 'mqtt.msgtype', kind: 'int'},
        {nk: 'remainingLength', ts: 'mqtt.len', kind: 'int'}
    ]},
    // CoAP (RFC 7252, udp:5683). The 4-byte fixed header. The token (tshark colon-formats it) and the
    // options/payload are verified byte-for-byte by round-trip + golden.
    coap: {tsLayer: 'coap', fields: [
        {nk: 'version', ts: 'coap.version', kind: 'int'},
        {nk: 'type', ts: 'coap.type', kind: 'int'},
        {nk: 'tokenLength', ts: 'coap.token_len', kind: 'int'},
        {nk: 'code', ts: 'coap.code', kind: 'int'},
        {nk: 'messageId', ts: 'coap.mid', kind: 'int'}
    ]},
    // EtherNet/IP encapsulation (ODVA, tcp/udp:44818). The little-endian header fields; tshark renders
    // them as 0x-hex but kind 'int' compares numerically (Number('0x0065')===101). The CIP/CPF command-
    // specific data is verified byte-for-byte by round-trip + golden (tshark's separate sub-tree).
    enip: {tsLayer: 'enip', fields: [
        {nk: 'command', ts: 'enip.command', kind: 'int'},
        {nk: 'length', ts: 'enip.length', kind: 'int'},
        {nk: 'sessionHandle', ts: 'enip.session', kind: 'int'},
        {nk: 'status', ts: 'enip.status', kind: 'int'},
        {nk: 'options', ts: 'enip.options', kind: 'int'}
    ]},
    // BACnet/IP (udp:47808). tshark names the BVLC layer 'bvlc'. type + function verify the header; the
    // BVLC Length (tshark renders it differently) and the NPDU/APDU payload are verified by round-trip.
    bacnet: {tsLayer: 'bvlc', fields: [
        {nk: 'type', ts: 'bvlc.type', kind: 'hexcode'},
        {nk: 'function', ts: 'bvlc.function', kind: 'int'}
    ]},
    // C37.118 (IEEE C37.118.2 synchrophasor). tshark names the layer 'synphasor'. Frame type / version /
    // size / id / fraction verify the common header; SOC (tshark renders it as an ISO date) and the CHK
    // are verified byte-for-byte by round-trip + golden.
    c37118: {tsLayer: 'synphasor', fields: [
        {nk: 'sync.frameType', ts: 'synphasor.frtype', kind: 'int'},
        {nk: 'sync.version', ts: 'synphasor.version', kind: 'int'},
        {nk: 'framesize', ts: 'synphasor.frsize', kind: 'int'},
        {nk: 'idcode', ts: 'synphasor.idcode_stream_source', kind: 'int'},
        {nk: 'fractionOfSecond', ts: 'synphasor.fracsec_raw', kind: 'int'}
    ]},
    // DNP3 (IEEE 1815, tcp/udp:20000) Data Link header. The control sub-bits and LE dest/src addresses
    // verify the header decode; the header CRC (tshark shows it LE-interpreted as a value, we keep the
    // raw bytes) and the data-block payload are verified byte-for-byte by round-trip + golden.
    dnp3: {tsLayer: 'dnp3', fields: [
        {nk: 'start', ts: 'dnp3.start', kind: 'hexcode'},
        {nk: 'length', ts: 'dnp3.len', kind: 'int'},
        {nk: 'control.functionCode', ts: 'dnp3.ctl.prifunc', kind: 'int'},
        {nk: 'control.dir', ts: 'dnp3.ctl.dir', kind: 'int'},
        {nk: 'control.prm', ts: 'dnp3.ctl.prm', kind: 'int'},
        {nk: 'destination', ts: 'dnp3.dst', kind: 'int'},
        {nk: 'source', ts: 'dnp3.src', kind: 'int'}
    ]},
    // Modbus/TCP (tcp:502). tshark splits it into an 'mbtcp' layer (MBAP header) and a 'modbus' layer
    // (PDU); the mapping verifies the 7-byte MBAP header against 'mbtcp'. The function code + data are
    // verified byte-for-byte by the round-trip + golden (they live in tshark's separate 'modbus' layer).
    modbus: {tsLayer: 'mbtcp', fields: [
        {nk: 'transactionId', ts: 'mbtcp.trans_id', kind: 'int'},
        {nk: 'protocolId', ts: 'mbtcp.prot_id', kind: 'int'},
        {nk: 'length', ts: 'mbtcp.len', kind: 'int'},
        {nk: 'unitId', ts: 'mbtcp.unit_id', kind: 'int'}
    ]},
    // OSPFv2 (RFC 2328). Common header + Hello fields. tshark names the router id 'ospf.srcrouter' and
    // the message type 'ospf.msg'. checksum uses kind 'int' (Number('0xf694')).
    ospf: {tsLayer: 'ospf', fields: [
        {nk: 'version', ts: 'ospf.version', kind: 'int'},
        {nk: 'type', ts: 'ospf.msg', kind: 'int'},
        {nk: 'packetLength', ts: 'ospf.packet_length', kind: 'int'},
        {nk: 'routerId', ts: 'ospf.srcrouter', kind: 'str'},
        {nk: 'areaId', ts: 'ospf.area_id', kind: 'str'},
        {nk: 'checksum', ts: 'ospf.checksum', kind: 'int'},
        {nk: 'auType', ts: 'ospf.auth.type', kind: 'int'},
        {nk: 'hello.networkMask', ts: 'ospf.hello.network_mask', kind: 'str'},
        {nk: 'hello.helloInterval', ts: 'ospf.hello.hello_interval', kind: 'int'},
        {nk: 'hello.routerDeadInterval', ts: 'ospf.hello.router_dead_interval', kind: 'int'},
        {nk: 'hello.routerPriority', ts: 'ospf.hello.router_priority', kind: 'int'},
        {nk: 'hello.designatedRouter', ts: 'ospf.hello.designated_router', kind: 'str'},
        {nk: 'hello.neighbors.0', ts: 'ospf.hello.active_neighbor', kind: 'str'}
    ]},
    // VRRP v2/v3 (RFC 3768/5798). checksum uses kind 'int' (Number('0xb952')===47442). The virtual IP
    // address list is verified via addresses[0]; tshark names it vrrp.ip_addr.
    vrrp: {tsLayer: 'vrrp', fields: [
        {nk: 'version', ts: 'vrrp.version', kind: 'int'},
        {nk: 'type', ts: 'vrrp.type', kind: 'int'},
        {nk: 'vrid', ts: 'vrrp.virt_rtr_id', kind: 'int'},
        {nk: 'priority', ts: 'vrrp.prio', kind: 'int'},
        {nk: 'count', ts: 'vrrp.addr_count', kind: 'int'},
        {nk: 'authType', ts: 'vrrp.auth_type', kind: 'int'},
        {nk: 'adverInt', ts: 'vrrp.adver_int', kind: 'int'},
        {nk: 'checksum', ts: 'vrrp.checksum', kind: 'int'},
        {nk: 'addresses.0', ts: 'vrrp.ip_addr', kind: 'str'}
    ]},
    // BFD Control (RFC 5880). State + discriminators + intervals verify the 24-byte mandatory section.
    bfd: {tsLayer: 'bfd', fields: [
        {nk: 'version', ts: 'bfd.version', kind: 'int'},
        {nk: 'diagnostic', ts: 'bfd.diag', kind: 'int'},
        {nk: 'flags.state', ts: 'bfd.sta', kind: 'int'},
        {nk: 'detectMult', ts: 'bfd.detect_time_multiplier', kind: 'int'},
        {nk: 'length', ts: 'bfd.message_length', kind: 'int'},
        {nk: 'myDiscriminator', ts: 'bfd.my_discriminator', kind: 'int'},
        {nk: 'yourDiscriminator', ts: 'bfd.your_discriminator', kind: 'int'},
        {nk: 'desiredMinTxInterval', ts: 'bfd.desired_min_tx_interval', kind: 'int'},
        {nk: 'requiredMinRxInterval', ts: 'bfd.required_min_rx_interval', kind: 'int'}
    ]},
    // GRE base header + optional Key/Sequence. proto (hexcode) + flags + key/seq verify the header walk;
    // the inner eth/ip/icmp layers are compared via their own mappings (duplicate layer skipped).
    gre: {tsLayer: 'gre', fields: [
        {nk: 'protocolType', ts: 'gre.proto', kind: 'hexcode'},
        {nk: 'flags.version', ts: 'gre.flags.version', kind: 'int'},
        {nk: 'flags.checksum', ts: 'gre.flags.checksum', kind: 'int'},
        {nk: 'flags.key', ts: 'gre.flags.key', kind: 'int'},
        {nk: 'flags.sequence', ts: 'gre.flags.sequence_number', kind: 'int'},
        {nk: 'keyValue', ts: 'gre.key', kind: 'hexcode'},
        {nk: 'sequenceNumber', ts: 'gre.sequence_number', kind: 'int'}
    ]},
    // GENEVE base header. proto_type (hexcode) + vni verify the tunnel; the inner eth/ip/icmp layers are
    // compared via their own mappings (the outer+inner duplicate layer is skipped by the duplicate guard).
    geneve: {tsLayer: 'geneve', fields: [
        {nk: 'version', ts: 'geneve.version', kind: 'int'},
        {nk: 'optLen', ts: 'geneve.option.length', kind: 'int'},
        {nk: 'vni', ts: 'geneve.vni', kind: 'int'},
        {nk: 'protocolType', ts: 'geneve.proto_type', kind: 'hexcode'},
        {nk: 'oam', ts: 'geneve.flags.oam', kind: 'int'},
        {nk: 'critical', ts: 'geneve.flags.critical', kind: 'int'}
    ]},
    // L2TP v2 header. tunnel/session/Ns/Nr and flags.type/version verify the flag-conditional header
    // walk landed on the right offsets. The AVPs are nested + repeated under tshark's per-AVP groups
    // (DFS-unreliable, like the DHCPv6 options), so they are verified byte-for-byte by round-trip+golden.
    l2tp: {tsLayer: 'l2tp', fields: [
        {nk: 'length', ts: 'l2tp.length', kind: 'int'},
        {nk: 'tunnelId', ts: 'l2tp.tunnel', kind: 'int'},
        {nk: 'sessionId', ts: 'l2tp.session', kind: 'int'},
        {nk: 'ns', ts: 'l2tp.Ns', kind: 'int'},
        {nk: 'nr', ts: 'l2tp.Nr', kind: 'int'},
        {nk: 'flags.version', ts: 'l2tp.version', kind: 'int'},
        {nk: 'flags.type', ts: 'l2tp.type', kind: 'int'}
    ]},
    dhcpv6: {tsLayer: 'dhcpv6', fields: [
        {nk: 'msgType', ts: 'dhcpv6.msgtype', kind: 'int'},
        // tshark shows the xid as 0x-hex; our transactionId is a bare hex string → hexcode strips 0x.
        {nk: 'transactionId', ts: 'dhcpv6.xid', kind: 'hexcode'}
        // NB: the per-option code is deliberately NOT mapped — tshark nests options and getTsharkField's
        // DFS does not guarantee the FIRST option (it returns whichever dhcpv6.option.type it reaches
        // first), so a direct options.0.code comparison would be unreliable. The option walk is covered
        // byte-for-byte by the round-trip + golden instead.
    ]}
}

function getByPath(obj: any, dottedPath: string): unknown {
    return dottedPath.split('.').reduce((o: any, key: string): any => (o == null ? undefined : o[key]), obj)
}

// tshark nests a field directly in the layer or inside child objects ("*_tree", "Queries"/"Answers"
// record groups, …). Search depth-first, direct hit first — a strict superset of a one-level lookup,
// so shallow fields resolve exactly as before while deep ones (e.g. dns.qry.name under Queries →
// record) are now reachable instead of silently skipped.
function getTsharkField(layer: {[field: string]: unknown} | undefined, field: string): unknown {
    if (!layer || typeof layer !== 'object') return undefined
    if (field in layer) return layer[field]
    for (const value of Object.values(layer)) {
        if (value && typeof value === 'object' && !Array.isArray(value)) {
            const found: unknown = getTsharkField(value as {[field: string]: unknown}, field)
            if (found !== undefined) return found
        }
    }
    return undefined
}

function normalizedPair(kind: ValueKind, nkValue: unknown, tsRaw: unknown): [string | number, string | number] {
    const ts: unknown = Array.isArray(tsRaw) ? tsRaw[0] : tsRaw
    switch (kind) {
        case 'mac': return [String(nkValue).toLowerCase(), String(ts).toLowerCase()]
        case 'hexcode': return [String(nkValue).replace(/^0x/i, '').toLowerCase(), String(ts).replace(/^0x/i, '').toLowerCase()]
        case 'int': return [Number(nkValue), Number(ts)]
        case 'str': return [String(nkValue), String(ts)]
    }
}

test('differential oracle: netkitty decode matches tshark for the mapped core fields', {skip: !tsharkAvailable() && 'tshark not installed'}, async (): Promise<void> => {
    const mismatches: string[] = []
    let compared: number = 0
    for (const name of AllPacketFixtureNames()) {
        const packet: Buffer = LoadPacket(name).buffer
        let layers: TsharkLayers
        try {
            layers = tsharkLayers(packet)
        } catch (e) {
            continue // tshark refused this frame; not a decode discrepancy
        }
        const decoded: CodecDecodeResult[] = await Decode(packet)
        //tshark's frame.protocols lists the dissected layer names in order. A layer that appears
        //more than once (tunneling / SRv6 / IP-in-IP) is ambiguous under -T json, which collapses
        //the duplicate key to a single last-wins object — so skip those layers rather than compare
        //netkitty's outer header against tshark's shadowed inner one.
        const protocols: string[] = String(getTsharkField(layers.frame as {[field: string]: unknown} | undefined, 'frame.protocols') || '').split(':')
        for (const layer of decoded) {
            const map: LayerMap | undefined = MAPPINGS[layer.id]
            if (!map) continue
            if (protocols.filter((protocol: string): boolean => protocol === map.tsLayer).length > 1) continue
            const tsLayer: {[field: string]: unknown} | undefined = layers[map.tsLayer] as {[field: string]: unknown} | undefined
            if (!tsLayer) continue
            for (const field of map.fields) {
                const nkValue: unknown = getByPath(layer.data, field.nk)
                const tsValue: unknown = getTsharkField(tsLayer, field.ts)
                if (nkValue === undefined || nkValue === null || tsValue === undefined) continue
                const [a, b] = normalizedPair(field.kind, nkValue, tsValue)
                compared++
                if (a !== b) mismatches.push(`${name} · ${layer.id}.${field.nk}: netkitty=${JSON.stringify(a)} tshark=${JSON.stringify(b)} (${field.ts})`)
            }
        }
    }
    assert.ok(compared > 50, `expected the oracle to compare many fields, only compared ${compared}`)
    assert.deepStrictEqual(mismatches, [], `netkitty disagreed with tshark on ${mismatches.length} field(s):\n  ${mismatches.join('\n  ')}`)
})
