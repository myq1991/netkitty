import {Codec} from '../../lib/codec/Codec'
import {FlexibleObject} from '../../lib/codec/lib/FlexibleObject'
import {UInt8ToHex} from '../../lib/codec/lib/NumberToHex'

async function DecodeAndEncode(packet: string): Promise<void> {
    const packetBuffer: Buffer = Buffer.from(packet, 'base64')
    console.log('packetBuffer:', packetBuffer.toString('hex'))
    const codec = new Codec()
    const decodeResult = await codec.decode(packetBuffer)
    console.log(decodeResult)
    // console.log(JSON.stringify(decodeResult, null, 2))
    for (let i = 0; i < 1; i++) {
        const encodeResult = await codec.encode(decodeResult)
    }
    // const encodeResult = await codec.encode(decodeResult)
    // console.log('encodeResult:', encodeResult.packet.toString('hex'))
    // console.log('packetBuffer===encodeResult', packetBuffer.toString('hex') === encodeResult.packet.toString('hex'))
    // const decodeResult1 = await codec.decode(encodeResult.packet)
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

async function UDP_Codec(packet: string): Promise<void> {
    await DecodeAndEncode(packet)
}

(async (): Promise<void> => {
    console.time('GOOSE')
    await GOOSE_Codec('AaD0CC93AKD0CC93iLgAAQCRAAAAAGGBhoAaR0VEZXZpY2VGNjUwL0xMTjAkR08kZ2NiMDGBAwCcQIIYR0VEZXZpY2VGNjUwL0xMTjAkR09PU0UxgwtGNjUwX0dPT1NFMYQIOG6780IXKAqFAQGGAQuHAQCIAQGJAQCKAQirIIMBAIQDAwAAgwEAhAMDAACDAQCEAwMAAIMBAIQDAwAA')
    console.timeEnd('GOOSE')

    console.time('IEC61850SampleValues')
    await IEC61850SampleValues_Codec('AQzNBAAByv7A/+5piLpAAQBmAAAAAGBcgAEBolcwVYAENDAwMYICCDaDBAAAAAGFAQKHQAADpBwAAAAAAAAgrAAAAAD//DyAAAAAAAAAAUgAACAAAPOi+AAAAAAAC1wyAAAAAP8BRogAAAAAAABFsgAAIAA=')
    console.timeEnd('IEC61850SampleValues')

    // await IPv4_Codec('AQBeAAD7RvyxjrRvCABFAABDFi9AAP8Rwg7AqAHI4AAA+61EFOkALwQ6AAAAAAABAAAAAAAACl9seXJhLW1kbnMEX3VkcAVsb2NhbAAADIAB')
    console.time('IPv4')
    await IPv4_Codec('AAAAAAAAAAAAAAAACABLAABseDcAAEABdS1/AAABfwAAAYYWAAAAAgIQAAIAAAACAAQABQAGAO8AAAAAKVCMCgABkk2uRRMODAAICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc=')
    console.timeEnd('IPv4')

    console.time('ARP')
    await ARP_Codec('////////AFDCV7MQCAYAAQgABgQAAQBQwlezEMCorNcAAAAAAADAqKwBAAAAAAAAAAAAAAAWOgAFAgAA')
    console.timeEnd('ARP')

    // await TCP_Codec('jrqXwYfpMsUZ/NE3CABFAABAAABAAEAG7RnAqAGf3LWuof8nAbtj7USXAAAAALAC//8W3wAAAgQFtAEDAwYBAQgKrHN8owAAAAAEAgAA')
    console.time('TCP')
    await TCP_Codec('MsUZ/NE3jrqXwYfpCABFAAJtAABAADMGCAYr+E9GwKgBnwBQxWyUVlJ28OAPzYAYAf/ikQAAAQEICu648gfnwk9J+s/+/j/vP/v7/uz/7O/72352Oswm1bo1vf3hf+t/9vf8CRLU/Od/3l/1X/49/yCJC4U2G3u23cjEvL4q2un8J8mR/z0kh/7ZG/ILfmG2WOl67ld1+dnvvvdM/VjS/nm9zEqiLcsVyZhIHfokx4F6iHXqBsfc0VBOtoXhIKYQx/K//EP/esL9v/gr/jzAuQUY0AhOI6A5Kn109O03b16+fk8YIPQvojT7dbYsswl7mx8dHZ8RYhSz/ed/xJ9NM/o1INb5rLjI63FWELRX/+hfzX9RzEmD/a/+qj/IgY1xAsCanqbV6pqXCYnkPNP/1d//N1KQm/4jf/Xezt79lKj2n/89fypNA6lJfLBDy4whQoTPJKfhjRdF0ZJ3fTmeLgnW3/LXnJ28/M//sj9y52Bn99P9g4f/+Z/4dwKdNKVv/vM//K+jWf3P/4Y/mr5P7+3u7FJURotwuw/2PuVmwM9D3CgV+tX+/viu6BL8avUQfT+sJDltSOZi9pJ0LSmhO+P1JJPfbeKjq9joIzzwsNLPxQFts4t064L+peDgjjj9ikAs6MBMiedKbyyyJanRmjkAECja+D1IK36+/el3Hj57svfqwbN9WFWB5uDSb1gpZlcYDvdzoEzqu/cR+8Y0AC+Vh24oi2fbiONMzgKn3po7h5ze4VYf/3RDyTvYhKdkQ7bugBTuS1q+PC8uqMHHPrpsLTyMiVY0Q5Nqdk1/PL47bxfwDQpiDQqC/h9WtstCH04AAA0KMA0KDQo=')
    console.timeEnd('TCP')

    // await TCP_Codec('MsUZ/NE3jrqXwYfpCABFAAAoAABAAEAG4N0NQoppwKgBnwG7wHisAGbXAAAAAFAEAACA4gAA')
    console.time('UDP')
    await UDP_Codec('////////CAAnzP1BCABFAAD/uTJAAEAR+6XAqAHGwKgB/wCKAIoA62oQEQp9csCoAcYAigDVAAAgRkFGRUZEQ0FDQUNBQ0FDQUNBQ0FDQUNBQ0FDQUNBQUEAIEZIRVBGQ0VMRUhGQ0VQRkZGQUNBQ0FDQUNBQ0FDQUJOAP9TTUIlAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEQAAOwAAAAAAAAAAAAAAAAAAAAAAAAA7AFYAAwABAAEAAgBMAFxNQUlMU0xPVFxCUk9XU0UAAe2A/AoAUFRTAAAAAAAAAAAAAAAAAAYBA5qBAA8BVapwdHMgc2VydmVyIChTYW1iYSwgVWJ1bnR1KQA=')
    console.timeEnd('UDP')


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
