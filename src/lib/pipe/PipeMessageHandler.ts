import {MessageClient, MessageConnection, MessageEvent} from 'socket-ipc'
import {PipeMessage, PipeMessageType} from './PipeMessage'
import EventEmitter from 'events'
import {PipeClient} from './PipeClient'
import {PipeClientSocket} from './PipeClientSocket'
import {UnknownPipeMessageTypeError} from '../../errors/UnknownPipeMessageTypeError'
import {ActionNotFoundError} from '../../errors/ActionNotFoundError'

export class PipeMessageHandler extends EventEmitter {

    readonly #owner: PipeClient | PipeClientSocket

    readonly #socket: MessageConnection | MessageClient

    constructor(owner: PipeClient | PipeClientSocket, socket: MessageConnection)
    constructor(owner: PipeClient | PipeClientSocket, socket: MessageClient)
    constructor(owner: PipeClient | PipeClientSocket, socket: MessageConnection | MessageClient) {
        super()
        this.#owner = owner
        this.#socket = socket
        if (this.#socket instanceof MessageConnection) {
            this.#socket.on('message', (message: MessageEvent): void => this.onMessageHandler(message))
        } else {
            this.#socket.on('message', (message: MessageEvent): void => this.onMessageHandler(message))
        }
    }

    /**
     * On pipe message handler
     * @param message
     * @protected
     */
    protected onMessageHandler(message: MessageEvent): void {
        const pipeMessage: PipeMessage = new PipeMessage(message.data as string)
        switch (pipeMessage.type) {
            case PipeMessageType.EVENT: {
                const args: any[] = pipeMessage.payload as any[]
                const eventName: string = args.shift()
                this.#owner.emit(eventName, ...args)
            }
                break
            case PipeMessageType.REQUEST: {
                const args: any[] = pipeMessage.payload as any[]
                const actionName: string = args.shift()
                const action: (...args: any[]) => Promise<any> = this.#owner.actions[actionName]
                if (action) {
                    action.call(this.#owner, ...args)
                        .then(response => {
                            pipeMessage.type = PipeMessageType.RESPONSE_OK
                            pipeMessage.payload = response
                            this.#socket.send(pipeMessage.serialize())
                        })
                        .catch((error: NodeJS.ErrnoException): void => {
                            pipeMessage.type = PipeMessageType.RESPONSE_ERR
                            pipeMessage.payload = {
                                message: error.message,
                                errno: error.errno,
                                code: error.code
                            }
                            this.#socket.send(pipeMessage.serialize())
                        })
                } else {
                    pipeMessage.type = PipeMessageType.RESPONSE_ERR
                    const actionNotFoundError = new ActionNotFoundError(`Action ${actionName} not found`)
                    pipeMessage.payload = {
                        message: actionNotFoundError.message,
                        errno: actionNotFoundError.errno,
                        code: actionNotFoundError.code
                    }
                    this.#socket.send(pipeMessage.serialize())
                }
            }
                break
            case PipeMessageType.RESPONSE_OK: {
                this.#owner.emit(pipeMessage.messageId, pipeMessage.payload)
            }
                break
            case PipeMessageType.RESPONSE_ERR: {
                const responseError: NodeJS.ErrnoException = new Error()
                responseError.message = pipeMessage.payload.message
                responseError.errno = pipeMessage.payload.errno
                responseError.code = pipeMessage.payload.code
                this.#owner.emit(pipeMessage.messageId, responseError)
            }
                break
            default: {
                this.#owner.emit('error', new UnknownPipeMessageTypeError(`Unknown pipe message type ${pipeMessage.type}`))
            }
        }
    }
}
