import {Codec} from '../../lib/codec/Codec'

(async (): Promise<void> => {
    const packet: string = 'AaD0CC93AKD0CC93iLgAAQCRAAAAAGGBhoAaR0VEZXZpY2VGNjUwL0xMTjAkR08kZ2NiMDGBAwCcQIIYR0VEZXZpY2VGNjUwL0xMTjAkR09PU0UxgwtGNjUwX0dPT1NFMYQIOG6780IXKAqFAQGGAQuHAQCIAQGJAQCKAQirIIMBAIQDAwAAgwEAhAMDAACDAQCEAwMAAIMBAIQDAwAA'
    const packetBuffer: Buffer = Buffer.from(packet, 'base64')
    console.log('packetBuffer:', packetBuffer.toString('hex'))
    const codec = new Codec()
    const decodeResult = await codec.decode(packetBuffer)
    // console.log(JSON.stringify(decodeResult, null, 2))
    // console.time('encode')
    // for(let i=0;i<100000;i++){
    //     await codec.encode(decodeResult)
    // }
    // console.timeEnd('encode')
    const encodeResult = await codec.encode(decodeResult)
    console.log('encodeResult:', encodeResult.toString('hex'))
    const decodeResult1 = await codec.decode(encodeResult)
    console.log(JSON.stringify(decodeResult1, null, 2))
})()
