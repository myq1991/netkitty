import {PipeServer} from '../lib/pipe/PipeServer'
import {PipeClient} from '../lib/pipe/PipeClient'
import {fork} from 'node:child_process'
import path from 'node:path'
import {Capture} from '../lib/nodepcap/Capture'
import {BindingCapture} from '../lib/nodepcap/lib/BindingCapture'
import {ErrorCode} from '../errors/common/ErrorCode'
import {PcapParser} from '../lib/pcap/lib/PcapParser'
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
        await pr.readPacket(info.offset, info.length)
    )
})
let pr: PcapReader
capture.start().then(() => {
    console.log('start!')
    pr = new PcapReader({filename: capture.temporaryFilename, watch: false})
})

