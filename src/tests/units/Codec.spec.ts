import {Codec} from '../../lib/codec/Codec'

(async (): Promise<void> => {
    const packet: string = 'AQzNAQNVABAAAANVgQAABoi4A1UAlgAAAABhgYuAGlBMMTEwMVBJR08wMS9MTE4wJEdPJGdvY2IwgQInEIIZUEwxMTAxUElHTzAxL0xMTjAkZHNHT09TRYMXUEwxMTAxUElHTzAxL0xMTjAuZ29jYjCECFjofgogQW4KhQEBhgIEsIcBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADUAAAEP//AACl0BFN'
    const packetBuffer: Buffer = Buffer.from(packet, 'base64')
    console.log('packetBuffer:', packetBuffer)
    const codec = new Codec()
    const decodeResult = await codec.decode(packetBuffer)
    // console.log(JSON.stringify(decodeResult, null, 2))
    console.log('decodeResult:', decodeResult)
    const encodeResult = await codec.encode(decodeResult)
    console.log('encodeResult:', encodeResult)
})()
