import EventEmitter from 'events'
import {MessageConnection} from 'socket-ipc'
import {PipeMessage, PipeMessageType} from './PipeMessage'
import {PipeMessageHandler} from './PipeMessageHandler'

export interface IPipeClientSocketOptions {
    id: string
    connection: MessageConnection
    actions: Record<string, (...args: any[]) => Promise<any>>
}

export class PipeClientSocket extends EventEmitter {

    readonly #id: string

    readonly #connection: MessageConnection

    #connected: boolean

    protected readonly pipeMessageHandler: PipeMessageHandler

    public readonly actions: Record<string, (...args: any[]) => Promise<any>> = {}

    /**
     * ClientId
     */
    public get id(): string {
        return this.#id
    }

    /**
     * Is client socket connected
     */
    public get connected(): boolean {
        return this.#connected
    }

    constructor(options: IPipeClientSocketOptions) {
        super()
        this.#id = options.id
        this.#connection = options.connection
        this.actions = options.actions ? options.actions : {}
        this.#connected = true
        this.#connection
            .on('error', (err: Error): boolean => this.emit('error', err))
            .once('close', (): void => {
                this.#connected = false
                this.emit('disconnect')
                this.removeAllListeners()
            })
        this.pipeMessageHandler = new PipeMessageHandler(this, this.#connection)
    }

    /**
     * Invoke client side action
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
                return reject(new Error('Socket is down'))
            }
            this.#connection.send(pipeMessage.serialize())
        })
    }

    /**
     * Notify event to pipe client
     * @param event
     * @param args
     */
    public notify(event: string, ...args: any[]): void {
        const pipeMessage: PipeMessage = new PipeMessage()
        pipeMessage.type = PipeMessageType.EVENT
        pipeMessage.payload = [event, ...args]
        if (this.connected) this.#connection.send(pipeMessage.serialize())
    }

    public on(eventName: 'disconnect', listener: () => void): this
    public on(eventName: string, listener: (...args: any) => void): this
    public on(eventName: string, listener: (...args: any) => void): this {
        super.on(eventName, listener)
        return this
    }

    public once(eventName: 'disconnect', listener: () => void): this
    public once(eventName: string, listener: (...args: any) => void): this
    public once(eventName: string, listener: (...args: any) => void): this {
        super.once(eventName, listener)
        return this
    }
}
