/**
 * Logical view of one frame's fixed-width index record. Physically stored columnar across TypedArrays
 * by the index store; this shape is what append/get/range/scan hand back.
 */
export type FrameIndexRecord = {
    index: number
    //Offset to the packet data within the source, for on-demand re-parsing.
    fileOffset: number
    capturedLength: number
    originalLength: number
    timestamp: number
    //Enum id of the innermost protocol (topProtocol).
    protocolId: number
    //Hash of the canonical n-tuple, direction-independent.
    conversationHash: number
    //1 if the frame's original source is the canonical endpointA (forward), else 0. Recovers the
    //src/dst direction that the canonicalized conversation key drops, so src/dst/port filters can be
    //answered from the index columns without re-decoding.
    directionForward: number
}
