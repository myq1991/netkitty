import {Coder} from '../../lib/coder/Coder'

(async (): Promise<void> => {
    const packet: string = 'AQzNAQNVABAAAANVgQAABoi4A1UAlgAAAABhgYuAGlBMMTEwMVBJR08wMS9MTE4wJEdPJGdvY2IwgQInEIIZUEwxMTAxUElHTzAxL0xMTjAkZHNHT09TRYMXUEwxMTAxUElHTzAxL0xMTjAuZ29jYjCECFjofgogQW4KhQEBhgIEsIcBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADUAAAEP//AACl0BFN'
    const packetBuffer: Buffer = Buffer.from(packet, 'base64')
    const coder = new Coder()
    const decodeResult = await coder.decode(packetBuffer)
    console.log(JSON.stringify(decodeResult, null, 2))
})()
