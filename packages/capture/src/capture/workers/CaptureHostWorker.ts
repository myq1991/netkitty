import {BindingCapture} from '../BindingCapture'
import {PipeClient} from '../../pipe/PipeClient'
import {PcapWriter, IPcapPacketInfo} from '@netkitty/pcap'
import {CaptureArgumentError, CaptureOpenError, CaptureFilterError} from '../../errors'

interface ISession {
    binding: BindingCapture
    writer: PcapWriter
}

interface ICreatePayload {
    id: string
    device: string
    filter: string
    emit: string
    temporaryFilename: string
}

//One host process for every capture. Each `create` spins up an independent native capture thread and
//its own pcap file writer, keyed by id; packets are streamed back tagged with that id.
const sessions: Map<string, ISession> = new Map<string, ISession>()

const pipeClient: PipeClient = new PipeClient({
    id: process.env.captureHostId!,
    socketPath: process.env.socketPath!,
    actions: {
        create: async (payload: ICreatePayload): Promise<void> => {
            if (sessions.has(payload.id)) return
            const writer: PcapWriter = new PcapWriter({
                filename: payload.temporaryFilename,
                includePacketData: payload.emit !== 'metadata'
            })
            //The native constructor only stores iface/filter; the device is not opened until start(), so
            //there is nothing device-related to catch here.
            const binding: BindingCapture = new BindingCapture({iface: payload.device, filter: payload.filter ? payload.filter : ''})
            binding.on('data', (data: Buffer, seconds: number, microseconds: number): void => writer.write(data, seconds, microseconds))
            writer.on('packet', (info: IPcapPacketInfo): void => pipeClient.notify('packet', {id: payload.id, info: info}))
            sessions.set(payload.id, {binding: binding, writer: writer})
        },
        start: async (payload: {id: string}): Promise<void> => {
            const session: ISession | undefined = sessions.get(payload.id)
            if (!session) return
            try {
                //start() opens the device THEN compiles/applies the filter — both surface here, not in the constructor.
                session.binding.start()
            } catch (e) {
                if (e instanceof TypeError) throw new CaptureArgumentError(e.message)
                const message: string = e instanceof Error ? e.message : String(e)
                //applyFilter() (native capture.cc) fails with these exact fixed strings; a pcap_open_live
                //failure carries libpcap's own device message, so anything else is a device-open failure.
                if (message.startsWith('Error compiling filter') || message === 'Error setting the filter') throw new CaptureFilterError(message)
                throw new CaptureOpenError(message)
            }
        },
        stop: async (payload: {id: string}): Promise<void> => {
            sessions.get(payload.id)?.binding.stop()
        },
        count: async (payload: {id: string}): Promise<number> => {
            const session: ISession | undefined = sessions.get(payload.id)
            return session ? session.writer.wroteCount : 0
        },
        setFilter: async (payload: {id: string, filter: string}): Promise<void> => {
            const session: ISession | undefined = sessions.get(payload.id)
            if (!session) return
            try {
                session.binding.setFilter(payload.filter)
            } catch (e) {
                throw e instanceof TypeError ? new CaptureArgumentError(e.message) : new CaptureFilterError(e instanceof Error ? e.message : String(e))
            }
        },
        destroy: async (payload: {id: string}): Promise<void> => {
            const session: ISession | undefined = sessions.get(payload.id)
            if (!session) return
            session.binding.stop()
            await session.writer.close()
            sessions.delete(payload.id)
        }
    }
}).once('exit', (): void => {
    const closings: Promise<void>[] = []
    for (const session of sessions.values()) {
        session.binding.stop()
        closings.push(session.writer.close())
    }
    Promise.all(closings).finally((): void => process.exit(0))
})
