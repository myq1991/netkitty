import {open, rm, FileHandle, FileReadResult} from 'node:fs/promises'
import {existsSync} from 'node:fs'
import path from 'node:path'
import {PcapReader} from './PcapReader'
import {PcapWriter, PcapWriterFormat} from './PcapWriter'
import {IPcapPacketInfo} from '@netkitty/pcap-core'

/**
 * A per-packet edit result. Bare fields default to the original packet's value, so `{seconds: 0}` retimes
 * without touching the bytes and `Buffer` replaces the bytes without touching the timestamp.
 */
export type PcapEditPacket = {
    frame?: Buffer
    seconds?: number
    microseconds?: number
}

/**
 * What a rewrite handler may return for one input packet:
 *   undefined            → keep the packet unchanged
 *   null | false         → drop the packet
 *   Buffer               → replace the frame bytes, keep the timestamp
 *   PcapEditPacket       → replace the given fields, keep the rest
 *   Array<Buffer|Packet> → emit several packets in order (expand); [] drops the packet
 */
export type PcapEditAction = void | null | false | Buffer | PcapEditPacket | Array<Buffer | PcapEditPacket>

/** Per-packet callback for PcapEdit.rewrite: receives a frame and its info, returns a PcapEditAction (keep/drop/replace/expand). */
export type PcapEditHandler = (frame: Buffer, info: IPcapPacketInfo) => PcapEditAction | Promise<PcapEditAction>

/** The mutable context a transform edits: the (copied) frame bytes and the packet's timestamp. */
export type PcapEditContext = {
    frame: Buffer
    seconds: number
    microseconds: number
}

/** A composable, keep-one-packet edit step. Mutate `ctx` in place (or return a replacement). */
export type PcapEditTransform = (ctx: PcapEditContext, info: IPcapPacketInfo) => void | PcapEditContext

/** Progress report for a whole-file operation. `ratio` is bytesProcessed/totalBytes, clamped to [0,1]. */
export interface IPcapProgress {
    ratio: number
    bytesProcessed: number
    totalBytes: number
    read: number
    written: number
}

/** Options for PcapEdit.rewrite: input/output paths, output format, the per-packet handler, and progress reporting. */
export interface IPcapRewriteOptions {
    input: string
    output: string
    /** output format (default 'pcap'); reading auto-detects pcap/pcapng and gzip/LZ4 regardless */
    format?: PcapWriterFormat
    onPacket: PcapEditHandler
    includePacketData?: boolean
    /** byte-ratio progress callback, throttled to whole-percent steps; a final 100% always fires */
    onProgress?: (progress: IPcapProgress) => void
    /** emit progress each time this many whole percent are crossed (default 1) */
    progressPercentStep?: number
}

/** Result of a rewrite/retime operation: count of packets read from the input and written to the output. */
export interface IPcapRewriteResult {
    read: number
    written: number
}

/** Time unit for durations (default microseconds). */
export type TimeUnit = 'us' | 'ms' | 's' | 'min'

/** A 1-based, inclusive frame-index window; `to` omitted means "to the end of the file". */
export interface FrameRange {
    from: number
    to?: number
}

/**
 * A single timing edit for PcapEdit.retime:
 *   scale            — multiply inter-packet gaps by `factor` (anchored at the range/file start)
 *   constantInterval — space packets by a constant gap (ignores original timing within the range)
 *   shift            — add a fixed offset to every timestamp from `range.from` onward (whole file if no range)
 *   setStart         — rebase so the first packet lands at (seconds, microseconds); whole file only
 */
export type RetimeEdit =
    | {type: 'scale', factor: number}
    | {type: 'constantInterval', interval: number, unit?: TimeUnit}
    | {type: 'shift', delta: number, unit?: TimeUnit}
    | {type: 'setStart', seconds: number, microseconds?: number}

/** Options for PcapEdit.retime: input/output paths, output format, the timing edit to apply, an optional frame range, and progress reporting. */
export interface IPcapRetimeOptions {
    input: string
    output: string
    format?: PcapWriterFormat
    edit: RetimeEdit
    /**
     * 1-based inclusive frame window; omitted = whole file. 'scale'/'constantInterval' honor from+to (and
     * propagate the net delta to later frames); 'shift' honors `from` only (suffix shift, `to` ignored);
     * 'setStart' rejects a range.
     */
    range?: FrameRange
    onProgress?: (progress: IPcapProgress) => void
    progressPercentStep?: number
}

const MICROS_PER_SECOND: number = 1000000
const UNIT_MICROS: Record<TimeUnit, number> = {us: 1, ms: 1000, s: 1000000, min: 60000000}

/**
 * Stream-based capture editing built on PcapReader + PcapWriter. `rewrite` runs every packet of an input
 * capture through a handler and writes the (kept / replaced / retimed / expanded) result to a new file —
 * reading transparently handles pcap/pcapng and gzip/LZ4, and you choose the output format. `patchInPlace`
 * covers the narrow case of overwriting one packet's bytes without rewriting the file. The static
 * transform factories (retiming, MAC rewrite, …) are ready-made steps to compose with `chain`.
 */
export class PcapEdit {

    /**
     * Read `input`, run each packet through `onPacket`, write the result to a fresh `output` file.
     * @param options
     */
    public static async rewrite(options: IPcapRewriteOptions): Promise<IPcapRewriteResult> {
        return PcapEdit.run({
            input: options.input,
            output: options.output,
            format: options.format,
            includePacketData: options.includePacketData === true,
            onProgress: options.onProgress,
            progressPercentStep: options.progressPercentStep,
            produce: async (frame: Buffer, info: IPcapPacketInfo): Promise<PcapEditContext[]> =>
                PcapEdit.normalize(await options.onPacket(frame, info), frame, info)
        })
    }

    /**
     * Retime a capture by one edit, optionally limited to a 1-based inclusive frame window. For a windowed
     * 'scale'/'constantInterval', every frame AFTER the window is shifted by the net time change introduced
     * inside it, so the timeline stays continuous — no hole, and no reordering of an originally-ordered
     * capture. Timestamps are microsecond-resolution (nanosecond input is truncated). Because propagation
     * is non-local, retime takes exactly one edit and is not composable with chain(); combine byte edits
     * (MAC, truncate) via rewrite() instead.
     * @param options
     */
    public static async retime(options: IPcapRetimeOptions): Promise<IPcapRewriteResult> {
        const apply: (frame: Buffer, info: IPcapPacketInfo) => PcapEditContext = PcapEdit.makeRetimer(options.edit, options.range)
        return PcapEdit.run({
            input: options.input,
            output: options.output,
            format: options.format,
            includePacketData: false,
            onProgress: options.onProgress,
            progressPercentStep: options.progressPercentStep,
            produce: (frame: Buffer, info: IPcapPacketInfo): PcapEditContext[] => [apply(frame, info)]
        })
    }

    /** Convert a value in the given unit (default microseconds) to integer microseconds. */
    public static micros(value: number, unit: TimeUnit = 'us'): number {
        return Math.round(value * PcapEdit.unitMicros(unit))
    }

    /**
     * Shared streaming engine for rewrite/retime: read `input`, run each packet through `produce`, write
     * the results to a fresh `output`, and report throttled byte-ratio progress with a terminal 100%.
     * @protected
     */
    protected static async run(options: {
        input: string
        output: string
        format?: PcapWriterFormat
        includePacketData: boolean
        onProgress?: (progress: IPcapProgress) => void
        progressPercentStep?: number
        produce: (frame: Buffer, info: IPcapPacketInfo) => Promise<PcapEditContext[]> | PcapEditContext[]
    }): Promise<IPcapRewriteResult> {
        if (path.resolve(options.input) === path.resolve(options.output)) {
            throw new Error('PcapEdit: input and output must be different files; write to a temp file, then rename, to edit in place')
        }
        //always a fresh file — PcapWriter would otherwise append to an existing output
        if (existsSync(options.output)) await rm(options.output)
        const writer: PcapWriter = new PcapWriter({filename: options.output, format: options.format, includePacketData: options.includePacketData})
        const step: number = options.progressPercentStep && options.progressPercentStep > 0 ? options.progressPercentStep : 1
        let read: number = 0
        let written: number = 0
        let lastPercent: number = -1
        const emitProgress = (bytesProcessed: number, force: boolean): void => {
            if (!options.onProgress) return
            const totalBytes: number = reader.totalBytes
            const ratio: number = totalBytes > 0 ? Math.min(1, bytesProcessed / totalBytes) : 1
            const percent: number = Math.floor(ratio * 100)
            if (!force && percent < lastPercent + step) return
            lastPercent = percent
            try {
                options.onProgress({ratio: ratio, bytesProcessed: bytesProcessed, totalBytes: totalBytes, read: read, written: written})
            } catch {
                //a throwing progress handler must not abort the operation
            }
        }
        const handle = async (info: IPcapPacketInfo): Promise<void> => {
            read += 1
            const frame: Buffer = await reader.readPacketData(info)
            const outs: PcapEditContext[] = await options.produce(frame, info)
            for (const out of outs) {
                writer.write(out.frame, out.seconds, out.microseconds)
                written += 1
            }
            emitProgress(info.offset + info.length, false)
        }
        const reader: PcapReader = new PcapReader({filename: options.input, onPacket: handle})
        try {
            await new Promise<void>((resolve: () => void, reject: (error: Error) => void): void => {
                reader.once('error', reject)
                reader.once('done', (): void => resolve())
                reader.start().catch(reject)
            })
            emitProgress(reader.totalBytes, true) //terminal 100%
        } finally {
            //stop the reader (no-op once done) and always flush/close the writer, even on a handler error
            await reader.close().catch((): void => undefined)
            await writer.close()
        }
        return {read: read, written: written}
    }

    /**
     * Build the stateful per-packet retiming function. Range membership is decided on the ORIGINAL
     * info.index; the shift carried to post-range frames is taken from the emitted (rounded/clamped) time
     * of the last in-range frame, so the window boundary stays exact.
     * @protected
     */
    protected static makeRetimer(edit: RetimeEdit, range?: FrameRange): (frame: Buffer, info: IPcapPacketInfo) => PcapEditContext {
        const from: number = range ? range.from : 1
        const to: number = range && range.to !== undefined ? range.to : Number.POSITIVE_INFINITY
        if (range) {
            if (!Number.isInteger(range.from) || range.from < 1) throw new Error('PcapEdit.retime: range.from must be a 1-based integer')
            if (range.to !== undefined && (!Number.isInteger(range.to) || range.to < range.from)) throw new Error('PcapEdit.retime: range.to must be an integer >= range.from')
            if (edit.type === 'setStart') throw new Error('PcapEdit.retime: a range is not supported for the setStart edit')
        }
        const intervalMicros: number = edit.type === 'constantInterval' ? Math.max(0, Math.floor(edit.interval * PcapEdit.unitMicros(edit.unit))) : 0
        const shiftMicros: number = edit.type === 'shift' ? Math.round(edit.delta * PcapEdit.unitMicros(edit.unit)) : 0
        const startMicros: number = edit.type === 'setStart' ? edit.seconds * MICROS_PER_SECOND + (edit.microseconds ?? 0) : 0
        if (edit.type === 'scale' && !(Number.isFinite(edit.factor) && edit.factor >= 0)) throw new Error('PcapEdit.retime: scale factor must be a finite number >= 0')

        let anchor: number | null = null //working micros of the first in-range frame (scale/constantInterval)
        let inRangeIndex: number = 0
        let shift: number = 0 //signed micros added to every frame after the range
        let base: number | null = null //first-frame micros, for setStart

        return (frame: Buffer, info: IPcapPacketInfo): PcapEditContext => {
            const ctx: PcapEditContext = {frame: frame, seconds: info.seconds, microseconds: info.microseconds}
            const t: number = ctx.seconds * MICROS_PER_SECOND + ctx.microseconds
            if (edit.type === 'setStart') {
                if (base === null) base = t
                PcapEdit.setMicros(ctx, startMicros + (t - base))
                return ctx
            }
            if (edit.type === 'shift') {
                //a windowed shift is a suffix shift: the `to` boundary is inert by design, so shift from `from` on
                if (info.index >= from) PcapEdit.setMicros(ctx, t + shiftMicros)
                return ctx
            }
            //scale / constantInterval
            if (info.index < from) return ctx //before the range: untouched
            if (info.index <= to) {
                if (anchor === null) {
                    anchor = t
                    inRangeIndex = 0
                }
                const target: number = edit.type === 'scale' ? Math.round(anchor + (t - anchor) * edit.factor) : anchor + inRangeIndex * intervalMicros
                const emitted: number = Math.max(0, Math.floor(target))
                ctx.seconds = Math.floor(emitted / MICROS_PER_SECOND)
                ctx.microseconds = emitted % MICROS_PER_SECOND
                shift = emitted - t //from the emitted (post-clamp) value, so the boundary gap is exact
                inRangeIndex += 1
                return ctx
            }
            //after the range: rigid translation by the net in-range delta, preserving the outbound gap
            PcapEdit.setMicros(ctx, t + shift)
            return ctx
        }
    }

    /**
     * Overwrite one packet's bytes in place, without rewriting the file. Valid only when `frame` is the
     * SAME length as the original packet (variable-length records can't grow/shrink in place) and the file
     * is uncompressed (a compressed file's on-disk offsets differ from the decompressed stream the parser
     * reported). Use `rewrite` for length-changing edits or compressed inputs.
     * @param filename
     * @param info the IPcapPacketInfo the reader reported for this packet
     * @param frame replacement bytes, exactly info.packetLength long
     */
    public static async patchInPlace(filename: string, info: IPcapPacketInfo, frame: Buffer): Promise<void> {
        if (frame.length !== info.packetLength) {
            throw new Error(`PcapEdit.patchInPlace: replacement must be the same length (packet is ${info.packetLength} bytes, got ${frame.length}); use rewrite() for length-changing edits`)
        }
        const fileHandle: FileHandle = await open(filename, 'r+')
        try {
            const magic: Buffer = Buffer.alloc(4)
            const head: FileReadResult<Buffer> = await fileHandle.read({buffer: magic, offset: 0, length: 4, position: 0})
            const isGzip: boolean = head.bytesRead >= 2 && magic[0] === 0x1f && magic[1] === 0x8b
            const isLz4: boolean = head.bytesRead >= 4 && magic.readUInt32BE(0) === 0x04224d18
            if (isGzip || isLz4) {
                throw new Error('PcapEdit.patchInPlace: cannot patch a compressed capture in place; rewrite() to an uncompressed file instead')
            }
            await fileHandle.write(frame, 0, frame.length, info.packetOffset)
        } finally {
            await fileHandle.close()
        }
    }

    /**
     * Compose transforms into a single rewrite handler. Each runs in order over the same context (the
     * copied frame bytes + timestamp); the result is one packet per input packet.
     * @param transforms
     */
    public static chain(...transforms: PcapEditTransform[]): PcapEditHandler {
        return (frame: Buffer, info: IPcapPacketInfo): PcapEditContext => {
            const ctx: PcapEditContext = {frame: frame, seconds: info.seconds, microseconds: info.microseconds}
            for (const transform of transforms) {
                const next: void | PcapEditContext = transform(ctx, info)
                if (next && next !== ctx) {
                    ctx.frame = next.frame
                    ctx.seconds = next.seconds
                    ctx.microseconds = next.microseconds
                }
            }
            return ctx
        }
    }

    /* ---- retiming transforms ---- */

    /**
     * Shift every timestamp by a fixed offset (seconds and/or microseconds; may be negative, clamped at 0)
     */
    public static shiftTime(deltaSeconds: number, deltaMicroseconds: number = 0): PcapEditTransform {
        return (ctx: PcapEditContext): void => {
            PcapEdit.setMicros(ctx, PcapEdit.toMicros(ctx) + deltaSeconds * MICROS_PER_SECOND + deltaMicroseconds)
        }
    }

    /**
     * Rebase the capture so its first packet lands at (seconds, microseconds), preserving every gap
     */
    public static setStartTime(seconds: number, microseconds: number = 0): PcapEditTransform {
        const start: number = seconds * MICROS_PER_SECOND + microseconds
        let base: number | null = null
        return (ctx: PcapEditContext): void => {
            const t: number = PcapEdit.toMicros(ctx)
            if (base === null) base = t
            PcapEdit.setMicros(ctx, start + (t - base))
        }
    }

    /**
     * Scale the inter-packet timing by a factor relative to the first packet (2 = twice as slow,
     * 0.5 = twice as fast); the first packet's timestamp is unchanged
     */
    public static scaleTime(factor: number): PcapEditTransform {
        let base: number | null = null
        return (ctx: PcapEditContext): void => {
            const t: number = PcapEdit.toMicros(ctx)
            if (base === null) base = t
            PcapEdit.setMicros(ctx, Math.round(base + (t - base) * factor))
        }
    }

    /**
     * Ignore the original timing and space packets by a constant interval (in `unit`, default microseconds),
     * starting from the first packet's timestamp. For a windowed version use PcapEdit.retime.
     */
    public static constantInterval(interval: number, unit: TimeUnit = 'us'): PcapEditTransform {
        const intervalMicros: number = Math.max(0, Math.floor(interval * PcapEdit.unitMicros(unit)))
        let index: number = 0
        let start: number = 0
        return (ctx: PcapEditContext): void => {
            if (index === 0) start = PcapEdit.toMicros(ctx)
            PcapEdit.setMicros(ctx, start + index * intervalMicros)
            index += 1
        }
    }

    /* ---- Ethernet MAC transforms (assume an Ethernet link layer; frames shorter than the field are left untouched) ---- */

    /** Set the destination MAC (Ethernet bytes 0..5), e.g. '00:11:22:33:44:55' */
    public static setDestinationMac(mac: string): PcapEditTransform {
        const bytes: Buffer = PcapEdit.parseMac(mac)
        return (ctx: PcapEditContext): void => { if (ctx.frame.length >= 6) bytes.copy(ctx.frame, 0) }
    }

    /** Set the source MAC (Ethernet bytes 6..11), e.g. '00:11:22:33:44:55' */
    public static setSourceMac(mac: string): PcapEditTransform {
        const bytes: Buffer = PcapEdit.parseMac(mac)
        return (ctx: PcapEditContext): void => { if (ctx.frame.length >= 12) bytes.copy(ctx.frame, 6) }
    }

    /** Swap the source and destination MAC addresses (Ethernet) */
    public static swapMac(): PcapEditTransform {
        return (ctx: PcapEditContext): void => {
            if (ctx.frame.length < 12) return
            const destination: Buffer = Buffer.from(ctx.frame.subarray(0, 6))
            ctx.frame.copy(ctx.frame, 0, 6, 12)
            destination.copy(ctx.frame, 6)
        }
    }

    /** Truncate frames longer than maxBytes (both captured and original length become the shorter size) */
    public static truncate(maxBytes: number): PcapEditTransform {
        return (ctx: PcapEditContext): void => { if (ctx.frame.length > maxBytes) ctx.frame = ctx.frame.subarray(0, maxBytes) }
    }

    /* ---- internals ---- */

    private static unitMicros(unit: TimeUnit | undefined): number {
        const factor: number | undefined = UNIT_MICROS[unit ?? 'us']
        if (factor === undefined) throw new Error(`PcapEdit: unknown time unit '${unit}' (expected 'us' | 'ms' | 's' | 'min')`)
        return factor
    }

    private static toMicros(ctx: PcapEditContext): number {
        return ctx.seconds * MICROS_PER_SECOND + ctx.microseconds
    }

    private static setMicros(ctx: PcapEditContext, micros: number): void {
        const safe: number = Math.max(0, Math.floor(micros))
        ctx.seconds = Math.floor(safe / MICROS_PER_SECOND)
        ctx.microseconds = safe % MICROS_PER_SECOND
    }

    private static parseMac(mac: string): Buffer {
        const parts: number[] = mac.split(/[:-]/).map((hex: string): number => parseInt(hex, 16))
        if (parts.length !== 6 || parts.some((byte: number): boolean => Number.isNaN(byte) || byte < 0 || byte > 255)) {
            throw new Error(`PcapEdit: invalid MAC address '${mac}' (expected six hex octets like 00:11:22:33:44:55)`)
        }
        return Buffer.from(parts)
    }

    private static normalize(action: PcapEditAction, frame: Buffer, info: IPcapPacketInfo): PcapEditContext[] {
        if (action === undefined) return [{frame: frame, seconds: info.seconds, microseconds: info.microseconds}]
        if (action === null || action === false) return []
        const items: Array<Buffer | PcapEditPacket> = Array.isArray(action) ? action : [action]
        return items.map((item: Buffer | PcapEditPacket): PcapEditContext => Buffer.isBuffer(item)
            ? {frame: item, seconds: info.seconds, microseconds: info.microseconds}
            : {
                //fall back to the original frame if `frame` is absent or not a Buffer (a null/garbage
                //frame must never reach writer.write and throw)
                frame: Buffer.isBuffer(item.frame) ? item.frame : frame,
                seconds: item.seconds !== undefined ? item.seconds : info.seconds,
                microseconds: item.microseconds !== undefined ? item.microseconds : info.microseconds
            })
    }
}
