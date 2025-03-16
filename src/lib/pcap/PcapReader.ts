import EventEmitter from 'events'

export interface IPcapReaderOptions {
    filename: string
}

export class PcapReader extends EventEmitter {

    protected readonly filename: string

    constructor(options: IPcapReaderOptions) {
        super()
        this.filename = options.filename

    }

    //TODO
}
