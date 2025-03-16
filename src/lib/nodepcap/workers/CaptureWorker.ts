import {BindingCapture} from '../lib/BindingCapture'
import {PipeClient} from '../../pipe/PipeClient'
import {IWrotePacketInfo, PcapWriter} from '../../pcap/PcapWriter'

const captureTemporaryFilename: string = process.env.captureTemporaryFilename!

const pcapWrite: PcapWriter = new PcapWriter({
    filename: captureTemporaryFilename
})

const bindingCapture: BindingCapture = new BindingCapture({
    iface: process.env.captureDevice!,
    filter: process.env.captureFilter
})

const pipeClient: PipeClient = new PipeClient({
    id: process.env.captureWorkerId!,
    socketPath: process.env.socketPath!,
    actions: {
        start: async (): Promise<void> => bindingCapture.start(),
        stop: async (): Promise<void> => bindingCapture.stop(),
        setFilter: async (filter: string): Promise<void> => bindingCapture.setFilter(filter)
    }
}).once('exit', (): Promise<void> => pcapWrite.close().finally((): void => process.exit(0)))

pcapWrite.on('packet', (wrotePacketInfo: IWrotePacketInfo): void => pipeClient.notify('packet', wrotePacketInfo))

bindingCapture.on('data', (data: Buffer, sec: number, usec: number): void => pcapWrite.write(data, sec, usec))
