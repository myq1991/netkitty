import {Codec} from '../../lib/codec/Codec'

async function DecodeAndEncode(packet: string): Promise<void> {
    const packetBuffer: Buffer = Buffer.from(packet, 'base64')
    console.log('packetBuffer:', packetBuffer.toString('hex'))
    const codec = new Codec()
    const decodeResult = await codec.decode(packetBuffer)
    console.log(JSON.stringify(decodeResult, null, 2))
    // const encodeResult = await codec.encode(decodeResult)
    // console.log('encodeResult:', encodeResult.toString('hex'))
    // const decodeResult1 = await codec.decode(encodeResult)
    // console.log(JSON.stringify(decodeResult1, null, 2))
}

async function GOOSE_Codec(packet: string): Promise<void> {
    await DecodeAndEncode(packet)
}

async function IEC61850SampleValues_Codec(packet: string): Promise<void> {
    await DecodeAndEncode(packet)
}

(async (): Promise<void> => {
    // await GOOSE_Codec('AaD0CC93AKD0CC93iLgAAQCRAAAAAGGBhoAaR0VEZXZpY2VGNjUwL0xMTjAkR08kZ2NiMDGBAwCcQIIYR0VEZXZpY2VGNjUwL0xMTjAkR09PU0UxgwtGNjUwX0dPT1NFMYQIOG6780IXKAqFAQGGAQuHAQCIAQGJAQCKAQirIIMBAIQDAwAAgwEAhAMDAACDAQCEAwMAAIMBAIQDAwAA')
    await IEC61850SampleValues_Codec('AQzNBAADyv7A/+5piLpAAgBmAAAAAGBcgAEBolcwVYAENDAwMoICDQ+DBAAAAAGFAQKHQP/8ji4AAAAA//+ECgAAAAAAA+5sAAAAAAAAAKQAACAA/xmXlwAAAAD/3F9rAAAAAAEJCGMAAAAA//7/ZQAAIAA=')
})()
