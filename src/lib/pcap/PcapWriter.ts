import EventEmitter from 'events'
import {createWriteStream, WriteStream} from 'node:fs'

export interface IPcapWriterOptions {
    filename: string
}

export class PcapWriter extends EventEmitter {

    protected readonly filename: string

    protected readonly writeStream: WriteStream

    constructor(options: IPcapWriterOptions) {
        super()
        this.filename = options.filename
        this.writeStream = createWriteStream(this.filename, {autoClose: false})
    }

    public async close(): Promise<void> {
        return new Promise((resolve, reject) => {
            this.writeStream.close(err => err ? reject(err) : resolve())
        })
    }

    //TODO
}
