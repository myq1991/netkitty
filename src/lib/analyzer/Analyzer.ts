import EventEmitter from 'events'
import {IAnalyzerOptions} from './interfaces/IAnalyzerOptions'
import {PcapReader} from '../pcap/PcapReader'

export class Analyzer extends EventEmitter {

    readonly #filename: string

    readonly #reader: PcapReader

    #started: boolean = false

    constructor(options: IAnalyzerOptions) {
        super()
        this.#filename = options.filename
        this.#reader = new PcapReader({filename: this.#filename})
    }

    public start() {
        if (this.#started) return
        this.#started = true
        this.#reader.start()
    }

    public stop() {

    }
}
