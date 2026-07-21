import {AsnType} from './PerDecoder'

/**
 * AcsiPdu — ASN.1 type descriptors for CMS (DL/T 2811-2024) ACSI service PDUs, transcribed from the
 * standard for the {@link PerDecoder} (ALIGNED BASIC-PER, §6.10). These live on the imperative side of the
 * codec's schema split; each service is one entry in {@link SERVICE_PDU}, keyed by its Service Code, so
 * adding a service is a local addition and never a core change. PER ignores the IMPLICIT `[n]` tags in the
 * printed notation (tags are a BER concern only), so they are omitted here — only the structure, order,
 * optionality and SIZE/value constraints matter.
 */

//Common ACSI reference types (DL/T 2811-2024 §7.3): plain VisibleStrings with a SIZE constraint.
const OBJECT_NAME: AsnType = {k: 'vstr', min: 0, max: 64}        //ObjectName ::= VisibleString(SIZE(0..64))   §7.3.1
const OBJECT_REFERENCE: AsnType = {k: 'vstr', min: 0, max: 129}  //ObjectReference ::= VisibleString(SIZE(0..129)) §7.3.2
//FunctionalConstraint ::= VisibleString(SIZE(2)) §7.4.1.2 — a fixed 2-char code (ST, MX, CF, …), not an enum.
const FUNCTIONAL_CONSTRAINT: AsnType = {k: 'vstr', min: 2, max: 2}

/**
 * GetAllDataDefinition-RequestPDU (SC 155, §8.3.5.3). A 3-field SEQUENCE (not extensible): a `reference`
 * CHOICE between a bare logical-device name and a logical-node reference, an OPTIONAL functional
 * constraint, and an OPTIONAL "reference after" cursor for paging. Verified byte-for-byte against a real
 * frame whose service data `22 00` + "SW111103SWI/LLN0" decodes as preamble(00) + choice-index(1,
 * lnReference) + length(16) + the octet-aligned reference.
 */
export const GET_ALL_DATA_DEFINITION_REQUEST: AsnType = {
    k: 'seq',
    fields: [
        {name: 'reference', type: {k: 'choice', alts: [
            {name: 'ldName', type: OBJECT_NAME},
            {name: 'lnReference', type: OBJECT_REFERENCE}
        ]}},
        {name: 'fc', type: FUNCTIONAL_CONSTRAINT, optional: true},
        {name: 'referenceAfter', type: OBJECT_REFERENCE, optional: true}
    ]
}

//Common ACSI integer/string base types (DL/T 2811-2024 §7.1). INT16U is fully constrained (fixed width
//in PER); INT32U is semi-constrained INTEGER(0..MAX) (length-prefixed octets); a bare VisibleString has no
//SIZE bound (length determinant + content).
const INT16U: AsnType = {k: 'int', lb: 0, ub: 65535}
const INT32U: AsnType = {k: 'int', lb: 0}
const VISIBLE_STRING: AsnType = {k: 'vstr'}

/**
 * AssociateNegotiate-RequestPDU / -ResponsePDU (SC 154, §8.15.1.3). The session-opening capability
 * exchange: negotiated APDU size, declared max ASDU size, and protocol version (0x201 = 2.1); the
 * response adds the model version string. All fields mandatory, not extensible. Verified against a real
 * frame whose 9-byte service data `fd e8 03 02 00 00 02 02 01` decodes to
 * {apduSize: 65000, asduSize: 131072, protocolVersion: 513}.
 */
export const ASSOCIATE_NEGOTIATE_REQUEST: AsnType = {
    k: 'seq',
    fields: [
        {name: 'apduSize', type: INT16U},
        {name: 'asduSize', type: INT32U},
        {name: 'protocolVersion', type: INT32U}
    ]
}

export const ASSOCIATE_NEGOTIATE_RESPONSE: AsnType = {
    k: 'seq',
    fields: [
        {name: 'apduSize', type: INT16U},
        {name: 'asduSize', type: INT32U},
        {name: 'protocolVersion', type: INT32U},
        {name: 'modelVersion', type: VISIBLE_STRING}
    ]
}

/**
 * GetAllDataValues-RequestPDU (SC 83, §8.3.4.3) is structurally identical to GetAllDataDefinition's request
 * (a reference CHOICE plus optional functional-constraint and paging cursor) per the standard, so it reuses
 * the same PER descriptor. Its response, by contrast, carries `Data` values encoded as GB/T 33602 TLV, not
 * PER, and is decoded separately (not via this PER descriptor table).
 */
export const GET_ALL_DATA_VALUES_REQUEST: AsnType = GET_ALL_DATA_DEFINITION_REQUEST

/**
 * Associate-RequestPDU (SC 1, §8.2.1.4). Both fields OPTIONAL: an optional server access-point reference
 * and an optional authentication parameter (signature certificate + signed UTC time + signed value). A real
 * frame carries both absent (service data `00` = the 2-bit preamble, both cleared). VisibleString129 =
 * VisibleString(SIZE(0..129)); UtcTime = OCTET STRING(SIZE(8)).
 */
export const ASSOCIATE_REQUEST: AsnType = {
    k: 'seq',
    fields: [
        {name: 'serverAccessPointReference', type: {k: 'vstr', min: 0, max: 129}, optional: true},
        {name: 'authenticationParameter', type: {k: 'seq', fields: [
            {name: 'signatureCertificate', type: {k: 'octstr'}},
            {name: 'signedTime', type: {k: 'octstr', size: 8}},
            {name: 'signedValue', type: {k: 'octstr'}}
        ]}, optional: true}
    ]
}

export interface ServicePdu {
    request?: AsnType
    response?: AsnType
}

/**
 * Service Code → PDU descriptors. Only services whose ASN.1 has been transcribed and verified against a
 * real frame appear here; an absent service (or an untranscribed direction) leaves the service data as
 * verbatim hex. GetAllDataDefinition's response references a not-yet-transcribed `DataDefinition` type, so
 * only the request is structured for now.
 */
export const SERVICE_PDU: Record<number, ServicePdu> = {
    1: {request: ASSOCIATE_REQUEST},
    83: {request: GET_ALL_DATA_VALUES_REQUEST},
    154: {request: ASSOCIATE_NEGOTIATE_REQUEST, response: ASSOCIATE_NEGOTIATE_RESPONSE},
    155: {request: GET_ALL_DATA_DEFINITION_REQUEST}
}

/** Service Code → name (DL/T 2811-2024 §6.1.2 Table 1), for the display label. */
export const SERVICE_NAMES: Record<number, string> = {
    1: 'Associate',
    2: 'Abort',
    3: 'Release',
    48: 'GetDataValues',
    83: 'GetAllDataValues',
    153: 'Test',
    154: 'AssociateNegotiate',
    155: 'GetAllDataDefinition',
    156: 'GetAllCBValues'
}
