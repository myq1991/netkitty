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
    155: {request: GET_ALL_DATA_DEFINITION_REQUEST}
}

/** Service Code → name (DL/T 2811-2024 §6.1.2 Table 1), for the display label. */
export const SERVICE_NAMES: Record<number, string> = {
    1: 'Associate',
    2: 'Abort',
    3: 'Release',
    48: 'GetDataValues',
    83: 'GetAllDataValues',
    154: 'AssociateNegotiate',
    155: 'GetAllDataDefinition',
    156: 'GetAllCBValues'
}
