import {CodecErrorInfo} from './CodecErrorInfo'

/**
 * A node in the Wireshark-style dissection tree: a field (or a container of fields) with the value,
 * its human label, the exact bytes it occupies in the packet, and a severity for expert-info
 * highlighting. This is a read-only projection over the same decode — no second parser.
 */
export type DissectionField = {
    name: string
    label?: string
    value?: unknown
    offset?: number
    length?: number
    rawBytes?: string
    severity: 'ok' | 'error'
    children?: DissectionField[]
}

/** One decoded layer's dissection: its id/name, the field tree, and any accumulated errors. */
export type DissectionLayer = {
    id: string
    name: string
    fields: DissectionField[]
    errors: CodecErrorInfo[]
}
