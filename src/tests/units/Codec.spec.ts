import {Codec} from '../../lib/codec/Codec'

(async (): Promise<void> => {
    const packet: string = 'AaD0CC93AKD0CC93iLgAAQCRAAAAAGGBhoAaR0VEZXZpY2VGNjUwL0xMTjAkR08kZ2NiMDGBAwCcQIIYR0VEZXZpY2VGNjUwL0xMTjAkR09PU0UxgwtGNjUwX0dPT1NFMYQIOG6780IXKAqFAQGGAQuHAQCIAQGJAQCKAQirIIMBAIQDAwAAgwEAhAMDAACDAQCEAwMAAIMBAIQDAwAA'
    const packetBuffer: Buffer = Buffer.from(packet, 'base64')
    console.log('packetBuffer:', packetBuffer)
    const codec = new Codec()
    const decodeResult = await codec.decode(packetBuffer)
    console.log(JSON.stringify(decodeResult, null, 2))
    // console.log('decodeResult:', decodeResult)
    const encodeResult = await codec.encode(decodeResult)
    console.log('encodeResult:', encodeResult)
})()
