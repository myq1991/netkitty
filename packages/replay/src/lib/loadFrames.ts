import {PcapReader, IPcapPacketInfo} from '@netkitty/pcap'
import {IReplayFrame} from './interfaces/IReplayFrame'

/**
 * Read a capture file (pcap / pcapng / cap, any endianness, µs or ns resolution) fully into memory as
 * replay frames, preserving each frame's timestamp so `multiplier` mode can reproduce the original
 * inter-frame timing. For very large captures prefer streaming your own frames into {@link Replay}.
 */
export async function loadFrames(filename: string): Promise<IReplayFrame[]> {
    const frames: IReplayFrame[] = []
    const reader: PcapReader = new PcapReader({
        filename: filename,
        onPacket: (info: IPcapPacketInfo): void => {
            frames.push({
                data: Buffer.from(info.packet, 'base64'),
                seconds: info.seconds,
                nanoseconds: info.nanoseconds
            })
        }
    })
    await new Promise<void>((resolve: () => void, reject: (error: Error) => void): void => {
        reader.once('done', (): void => resolve())
        reader.once('error', (error: Error): void => reject(error))
        reader.start().catch(reject)
    })
    await reader.close()
    return frames
}
