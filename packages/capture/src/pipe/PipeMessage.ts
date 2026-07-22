import {randomInt} from 'node:crypto'

export enum PipeMessageType {
    EVENT,
    REQUEST,
    RESPONSE_OK,
    RESPONSE_ERR
}

export interface IPipeMessage {
    messageId: string
    type: PipeMessageType
    payload: any
}

export class PipeMessage {

    #serialized: string

    #structured: IPipeMessage

    protected set structured(structured: IPipeMessage) {
        this.#structured = structured
        this.#serialized = JSON.stringify(this.#structured)
    }

    protected get structured(): IPipeMessage {
        return this.#structured
    }

    public get messageId(): string {
        return this.structured.messageId
    }

    public set type(type: PipeMessageType) {
        const structured: IPipeMessage = this.structured
        structured.type = type
        this.structured = structured
    }

    public get type(): PipeMessageType {
        return this.structured.type
    }

    public set payload(payload: any) {
        const structured: IPipeMessage = this.structured
        structured.payload = payload
        this.structured = structured
    }

    public get payload(): any {
        return this.structured.payload
    }

    constructor(serialized?: string) {
        if (serialized) {
            this.#serialized = serialized
            this.#structured = JSON.parse(serialized)
        } else {
            this.structured = {
                messageId: `PIPE_MSG_${Date.now().toString(16)}${randomInt(10000000, 99999999)}`,
                type: PipeMessageType.EVENT,
                payload: null
            }
        }
    }

    /**
     * Serialized pipe message
     */
    public serialize(): string {
        return this.#serialized
    }
}
