import EventEmitter from 'events'
import {MessageClient} from 'socket-ipc'
import {PipeMessage, PipeMessageType} from './PipeMessage'
import {PipeMessageHandler} from './PipeMessageHandler'
import {SocketDownError} from '../../errors/SocketDownError'

export interface IPipeClientOptions {
    id: string
    socketPath: string
    actions: Record<string, (...args: any[]) => Promise<any>>
}

export class PipeClient extends EventEmitter {

    #connected: boolean

    protected readonly id: string

    protected readonly socketPath: string

    protected readonly client: MessageClient

    protected readonly pipeMessageHandler: PipeMessageHandler

    public readonly actions: Record<string, (...args: any[]) => Promise<any>> = {}

    public get connected(): boolean {
        return this.#connected
    }

    constructor(options: IPipeClientOptions) {
        super()
        this.id = options.id
        this.socketPath = options.socketPath
        this.actions = options.actions
        this.#connected = true
        this.client = new MessageClient({path: this.socketPath})
        this.pipeMessageHandler = new PipeMessageHandler(this, this.client)
        this.client.on('close', (): boolean => this.#connected = false)
        this.client.start().then((): void => {
            this.client.send(Buffer.from(this.id).toString('base64'))
            this.emit('ready')
        })
    }

    /**
     * Invoke server side action
     * @param act
     * @param args
     */
    public async invoke(act: string, ...args: any[]): Promise<any> {
        return new Promise((resolve, reject): void => {
            const pipeMessage: PipeMessage = new PipeMessage()
            pipeMessage.type = PipeMessageType.REQUEST
            pipeMessage.payload = [act, ...args]
            this.once(pipeMessage.messageId, (resultOrError: any | Error): void => resultOrError instanceof Error ? reject(resultOrError) : resolve(resultOrError))
            if (!this.connected) {
                this.removeAllListeners(pipeMessage.messageId)
                return reject(new SocketDownError('Socket is down'))
            }
            this.client.send(pipeMessage.serialize())
        })
    }

    /**
     * Notify event to pipe server
     * @param event
     * @param args
     */
    public notify(event: string, ...args: any[]): void {
        const pipeMessage: PipeMessage = new PipeMessage()
        pipeMessage.type = PipeMessageType.EVENT
        pipeMessage.payload = [event, ...args]
        if (this.connected) this.client.send(pipeMessage.serialize())
    }

    public on(eventName: 'ready', listener: () => void): this
    public on(eventName: string, listener: (...args: any) => void): this
    public on(eventName: string, listener: (...args: any) => void): this {
        super.on(eventName, listener)
        return this
    }

    public once(eventName: 'ready', listener: () => void): this
    public once(eventName: string, listener: (...args: any) => void): this
    public once(eventName: string, listener: (...args: any) => void): this {
        super.once(eventName, listener)
        return this
    }

}
