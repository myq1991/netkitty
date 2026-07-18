import {GeneratePipeAddress} from '../GeneratePipeAddress'
import EventEmitter from 'events'
import {MessageConnection, MessageEvent, MessageServer} from 'socket-ipc'
import {PipeClientSocket} from './PipeClientSocket'

export interface IPipeServerOptions {
    actions?: Record<string, (...args: any[]) => Promise<any>>
}

export class PipeServer extends EventEmitter {

    readonly #server: MessageServer

    readonly #clientSocketMap: Map<string, PipeClientSocket> = new Map()

    protected readonly actions: Record<string, (...args: any[]) => Promise<any>> = {}

    public readonly socketPath: string

    public get clients(): Map<string, PipeClientSocket> {
        return this.#clientSocketMap
    }

    constructor(options?: IPipeServerOptions) {
        super()
        this.actions = options?.actions ? options.actions : {}
        this.socketPath = GeneratePipeAddress()
        this.#server = new MessageServer({path: this.socketPath})
        this.#server.on('connection', (connection: MessageConnection): void => {
            connection.once('message', (message: MessageEvent) => {
                const base64Id: string = message.data.toString()
                const clientId: string = Buffer.from(base64Id, 'base64').toString()
                const clientSocket: PipeClientSocket = new PipeClientSocket({
                    id: clientId,
                    connection: connection,
                    actions: this.actions
                })
                this.#clientSocketMap.set(clientId, clientSocket)
                clientSocket.once('disconnect', (): void => {
                    this.#clientSocketMap.delete(clientSocket.id)
                    this.emit('disconnect', clientSocket)
                })
                this.emit('connect', clientSocket)
            })
        })
        this.#server.start().then((): boolean => this.emit('ready'))
    }

    /**
     * Dispose pipe server
     */
    public dispose(): void {
        this.#server.stop()
        this.#clientSocketMap.clear()
    }

    public on(eventName: 'ready', listener: () => void): this
    public on(eventName: 'connect', listener: (clientSocket: PipeClientSocket) => void): this
    public on(eventName: 'disconnect', listener: (clientSocket: PipeClientSocket) => void): this
    public on(eventName: string, listener: (...args: any) => void): this
    public on(eventName: string, listener: (...args: any) => void): this {
        super.on(eventName, listener)
        return this
    }

    public once(eventName: 'ready', listener: () => void): this
    public once(eventName: 'connect', listener: (clientSocket: PipeClientSocket) => void): this
    public once(eventName: 'disconnect', listener: (clientSocket: PipeClientSocket) => void): this
    public once(eventName: string, listener: (...args: any) => void): this
    public once(eventName: string, listener: (...args: any) => void): this {
        super.once(eventName, listener)
        return this
    }
}
