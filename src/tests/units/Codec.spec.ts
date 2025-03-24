import {Codec} from '../../lib/codec/Codec'
import {FlexibleObject} from '../../lib/codec/lib/FlexibleObject'
import {UInt8ToHex} from '../../lib/codec/lib/NumberToHex'

async function DecodeAndEncode(packet: string): Promise<void> {
    const packetBuffer: Buffer = Buffer.from(packet, 'base64')
    console.log('packetBuffer:', packetBuffer.toString('hex'))
    const codec = new Codec()
    const decodeResult = await codec.decode(packetBuffer)
    console.log(JSON.stringify(decodeResult, null, 2))
    // const encodeResult = await codec.encode(decodeResult)
    // console.log('encodeResult:', encodeResult.toString('hex'))
    // console.log('packetBuffer===encodeResult', packetBuffer.toString('hex') === encodeResult.toString('hex'))
    // const decodeResult1 = await codec.decode(encodeResult)
    // console.log(JSON.stringify(decodeResult1, null, 2))
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

async function ARP_Codec(packet: string): Promise<void> {
    await DecodeAndEncode(packet)
}

async function TCP_Codec(packet: string): Promise<void> {
    await DecodeAndEncode(packet)
}

(async (): Promise<void> => {
    // await GOOSE_Codec('AaD0CC93AKD0CC93iLgAAQCRAAAAAGGBhoAaR0VEZXZpY2VGNjUwL0xMTjAkR08kZ2NiMDGBAwCcQIIYR0VEZXZpY2VGNjUwL0xMTjAkR09PU0UxgwtGNjUwX0dPT1NFMYQIOG6780IXKAqFAQGGAQuHAQCIAQGJAQCKAQirIIMBAIQDAwAAgwEAhAMDAACDAQCEAwMAAIMBAIQDAwAA')
    // await IEC61850SampleValues_Codec('AQzNBAAByv7A/+5piLpAAQBmAAAAAGBcgAEBolcwVYAENDAwMYICCDaDBAAAAAGFAQKHQAADpBwAAAAAAAAgrAAAAAD//DyAAAAAAAAAAUgAACAAAPOi+AAAAAAAC1wyAAAAAP8BRogAAAAAAABFsgAAIAA=')
    // await IPv4_Codec('AQBeAAD7RvyxjrRvCABFAABDFi9AAP8Rwg7AqAHI4AAA+61EFOkALwQ6AAAAAAABAAAAAAAACl9seXJhLW1kbnMEX3VkcAVsb2NhbAAADIAB')
    // await IPv4_Codec('AAAAAAAAAAAAAAAACABLAABseDcAAEABdS1/AAABfwAAAYYWAAAAAgIQAAIAAAACAAQABQAGAO8AAAAAKVCMCgABkk2uRRMODAAICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc=')
    // await ARP_Codec('////////AFDCV7MQCAYAAQgABgQAAQBQwlezEMCorNcAAAAAAADAqKwBAAAAAAAAAAAAAAAWOgAFAgAA')
    // await TCP_Codec('jrqXwYfpMsUZ/NE3CABFAABAAABAAEAG7RnAqAGf3LWuof8nAbtj7USXAAAAALAC//8W3wAAAgQFtAEDAwYBAQgKrHN8owAAAAAEAgAA')
    await TCP_Codec('jrqXwYfpMsUZ/NE3CABFAABAAABAAEAG7RnAqAGf3LWuof8nAbtj7USXAAAAALAC//8W3wAAAgQFtAEDAwYBAQgKrHN8owAAAAAEAgAA')
    // await TCP_Codec('MsUZ/NE3jrqXwYfpCABFAAAoAABAAEAG4N0NQoppwKgBnwG7wHisAGbXAAAAAFAEAACA4gAA')


    // const fobj = new FlexibleObject({
    //     cc1: true
    // })
    // fobj.cc2.bb3.setValue(true)
    //
    // fobj.c1.b1.ccc1.setValue('1')
    // fobj.c1.b1.ccc2.setValue(2)
    // fobj.c1.b1.ccc3.setValue(true)
    // // console.log(fobj.cc2.bb4.getValue(), fobj.cc2.bb4.isUndefined())
    // console.log(JSON.stringify(fobj.getValue(), null, 2))
    // console.log(fobj.c1.b1.ccc4.hhh6.getPath())
})()
