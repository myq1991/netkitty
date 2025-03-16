import {PipeServer} from '../lib/pipe/PipeServer'
import {PipeClient} from '../lib/pipe/PipeClient'
import {fork} from 'node:child_process'
import path from 'node:path'
import {Capture} from '../lib/nodepcap/Capture'
import {BindingCapture} from '../lib/nodepcap/lib/BindingCapture'
import {ErrorCode} from '../errors/common/ErrorCode'
import {PcapParser} from '../lib/pcap/PcapParser'
import {PcapReader} from '../lib/pcap/PcapReader'

// const bc = new BindingCapture({iface: 'en0'})
// bc.on('data', console.log)
// bc.start()

// console.log(GetNetworkInterfaces())

// new Capture({
//     device:'en0'
// })

const capture = new Capture({device: 'en0'})
capture.on('packet', async (info) => {
    console.log(
        info.index,
        await pr.readPacket(info.offset, info.length)
    )
})
console.log(capture.temporaryFilename)
let pr: PcapReader
capture.start().then((_pr) => {
    console.log('start!')
    pr = _pr
    setTimeout(async () => {
        await capture.pause()
        console.log('paused!')
        setTimeout(async () => {
            await capture.resume()
            console.log('resumed!')
            setTimeout(async () => {
                await capture.stop()
                console.log('stopped!')
            }, 60000)
        }, 10000)
    }, 10000)
})

