import {Codec} from '../../lib/codec/Codec'

async function DecodeAndEncode(packet: string): Promise<void> {
    const packetBuffer: Buffer = Buffer.from(packet, 'base64')
    console.log('packetBuffer:', packetBuffer.toString('hex'))
    const codec = new Codec()
    const decodeResult = await codec.decode(packetBuffer)
    // console.log(JSON.stringify(decodeResult, null, 2))
    const encodeResult = await codec.encode(decodeResult)
    console.log('encodeResult:', encodeResult.toString('hex'))
    const decodeResult1 = await codec.decode(encodeResult)
    console.log(JSON.stringify(decodeResult1, null, 2))
}

async function GOOSE_Codec(packet: string): Promise<void> {
    await DecodeAndEncode(packet)
}

async function IEC61850SampleValues_Codec(packet: string): Promise<void> {
    await DecodeAndEncode(packet)
}

async function IPv4_Codec(packet: string): Promise<void> {
    await DecodeAndEncode(packet)
}

(async (): Promise<void> => {
    // await GOOSE_Codec('AaD0CC93AKD0CC93iLgAAQCRAAAAAGGBhoAaR0VEZXZpY2VGNjUwL0xMTjAkR08kZ2NiMDGBAwCcQIIYR0VEZXZpY2VGNjUwL0xMTjAkR09PU0UxgwtGNjUwX0dPT1NFMYQIOG6780IXKAqFAQGGAQuHAQCIAQGJAQCKAQirIIMBAIQDAwAAgwEAhAMDAACDAQCEAwMAAIMBAIQDAwAA')
    // await IEC61850SampleValues_Codec('AQzNBAAByv7A/+5piLpAAQBmAAAAAGBcgAEBolcwVYAENDAwMYICCDaDBAAAAAGFAQKHQAADpBwAAAAAAAAgrAAAAAD//DyAAAAAAAAAAUgAACAAAPOi+AAAAAAAC1wyAAAAAP8BRogAAAAAAABFsgAAIAA=')
    // await IPv4_Codec('AQBeAAD7RvyxjrRvCABFAABDFi9AAP8Rwg7AqAHI4AAA+61EFOkALwQ6AAAAAAABAAAAAAAACl9seXJhLW1kbnMEX3VkcAVsb2NhbAAADIAB')
    await IPv4_Codec('AAAAAAAAAAAAAAAACABLAABseDcAAEABdS1/AAABfwAAAYYWAAAAAgIQAAIAAAACAAQABQAGAO8AAAAAKVCMCgABkk2uRRMODAAICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc=')
})()
