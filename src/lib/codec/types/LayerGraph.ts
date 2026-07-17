/**
 * A layer that may follow a given parent layer in the editor's "add next layer" menu. `discriminator`
 * tells the caller which parent field to set (and to what) so decode would route to this layer;
 * it is null for RawData, which may always follow any layer.
 */
export type NextLayer = {
    id: string
    name: string
    discriminator: {field: string, value: string | number} | null
}

/**
 * A parent layer whose discriminator field does not point at the child that actually follows it
 * (e.g. eth.etherType=0x86dd "IPv6" but the next layer is IPv4). Surfaced by the editor as a warning;
 * `suggestion` is the {field,value} that would align the parent with the actual child, or null when
 * the child is not reachable from that parent at all. Never blocks encoding — a lying packet is a
 * valid crafted packet.
 */
export type ConsistencyIssue = {
    index: number
    parentId: string
    childId: string
    field: string
    actual: string | number
    suggestion: {field: string, value: string | number} | null
    message: string
}
