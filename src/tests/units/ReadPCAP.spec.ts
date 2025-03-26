import {PcapReader} from '../../lib/pcap/PcapReader'
import path from 'node:path'

(async (): Promise<void> => {
    // const reader = new PcapReader({filename: path.resolve(__dirname, '../../../test.pcap'), watch: false})
    // const reader = new PcapReader({filename: '/Users/alex/Desktop/M8921_tx_arp_46.2.pcap', watch: false})
    const reader = new PcapReader({filename: '/Users/alex/Desktop/test.pcap', watch: false})
    reader.on('packet', (pcapPacketInfo) => {
        console.log(pcapPacketInfo.index)
    }).once('done', () => {
        console.log('done!')
    }).once('error',console.error)
    await reader.start()
})()
