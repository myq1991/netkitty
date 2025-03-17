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

let paused: boolean = false

const capture = new Capture({device: 'en0'})
capture.on('packet', async (info) => {
    const buf = await pr.readPacket(info.offset, info.length)
    console.log(info.index, buf.length)
    // console.log(
    //     info.index,
    //     buf
    // )
})
console.log(capture.temporaryFilename)
let pr: PcapReader
capture.start().then(() => {
    console.log('start!')
    // pr = _pr
    pr = new PcapReader({filename: capture.temporaryFilename, watch: true})
    setTimeout(async () => {
        await capture.pause()
        console.log('paused!')
        paused = true
        setTimeout(async () => {
            await capture.resume()
            console.log('resumed!')
            paused = false
            setTimeout(async () => {
                console.log('about to stop!!!!!')
                console.time('stopped!')
                await capture.stop()
                console.timeEnd('stopped!')
            }, 60000)
        }, 10000)
    }, 10000)
})

