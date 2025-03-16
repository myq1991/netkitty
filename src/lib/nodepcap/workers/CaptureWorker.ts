import {BindingCapture} from '../lib/BindingCapture'
import {PipeClient} from '../../pipe/PipeClient'

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
}).once('exit', (): void => process.exit(0))
bindingCapture.on('data', (data: Buffer, sec: number, usec: number): void => pipeClient.notify('packet', data, sec, usec))
