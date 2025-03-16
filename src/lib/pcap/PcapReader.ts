import EventEmitter from 'events'

export interface IPcapReaderOptions {
    filename: string
    watch?: boolean
}

export class PcapReader extends EventEmitter {

    protected readonly filename: string

    protected readonly watch: boolean

    constructor(options: IPcapReaderOptions) {
        super()
        this.filename = options.filename
        this.watch = !!options.watch
    }

    //TODO
}
