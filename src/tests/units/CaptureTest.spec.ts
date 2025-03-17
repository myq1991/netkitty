import {Capture} from '../../lib/nodepcap/Capture'
import {PcapReader} from '../../lib/pcap/PcapReader'

(async (): Promise<void> => {
    const capture = new Capture({device: 'en0'})
    const pcapReader: PcapReader = new PcapReader({filename: capture.temporaryFilename, watch: true})
    pcapReader.on('packet', async (info) => {
        // const buf = await pcapReader.readPacket(info.offset, info.length)
        // console.log(info.index, buf.length)
        console.log(info.index)
    })
    await capture.start()
    await pcapReader.start()
    console.log('started')
    await new Promise(resolve => setTimeout(resolve, 60000))
    console.time('paused')
    await capture.pause()
    console.timeEnd('paused')
    await new Promise(resolve => setTimeout(resolve, 300000))
    console.time('resumed')
    await capture.resume()
    console.timeEnd('resumed')
    await new Promise(resolve => setTimeout(resolve, 60000))
    console.time('stopped')
    await capture.stop()
    console.timeEnd('stopped')
})()
