import {BindingCapture} from '../lib/BindingCapture'
import {PipeClient} from '../../pipe/PipeClient'
import {PcapWriter, IPcapPacketInfo} from '@netkitty/pcap'

const captureTemporaryFilename: string = process.env.captureTemporaryFilename!

//`metadata` mode: the file still gets every packet, but the base64 bytes are dropped from the per-packet
//notification (skips the encoding and the largest part of the IPC payload). `full` (default) keeps them.
const includePacketData: boolean = process.env.captureEmit !== 'metadata'

const pcapWrite: PcapWriter = new PcapWriter({
    filename: captureTemporaryFilename,
    includePacketData: includePacketData
})

const bindingCapture: BindingCapture = new BindingCapture({
    iface: process.env.captureDevice!,
    filter: process.env.captureFilter ? process.env.captureFilter : ''
})

const pipeClient: PipeClient = new PipeClient({
    id: process.env.captureWorkerId!,
    socketPath: process.env.socketPath!,
    actions: {
        count: async (): Promise<number> => pcapWrite.wroteCount,
        start: async (): Promise<void> => bindingCapture.start(),
        stop: async (): Promise<void> => bindingCapture.stop(),
        setFilter: async (filter: string): Promise<void> => bindingCapture.setFilter(filter)
    }
}).once('exit', (): Promise<void> => pcapWrite.close().finally((): void => process.exit(0)))

pcapWrite.on('packet', (wrotePacketInfo: IPcapPacketInfo): void => pipeClient.notify('packet', wrotePacketInfo))

bindingCapture.on('data', (data: Buffer, sec: number, usec: number): void => pcapWrite.write(data, sec, usec))
