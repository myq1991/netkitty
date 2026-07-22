/**
 * Integration test: live packet capture.
 *
 * NOT part of `npm test` - requires a real network device and usually
 * elevated privileges (root/administrator). Run manually:
 *
 *   npm run build && node dist/tests/integration/Capture.spec.js [device]
 *
 * Default device: en0
 */
import {Capture} from '../../src/capture/Capture'
import {PcapReader} from '@netkitty/pcap'

const device: string = process.argv[2] ? process.argv[2] : 'en0'

const sleep = (ms: number): Promise<void> => new Promise((resolve): void => void setTimeout(resolve, ms))

;(async (): Promise<void> => {
    console.log(`capturing on device: ${device}`)
    const capture: Capture = new Capture({device: device})
    console.log('temporary pcap:', capture.temporaryFilename)

    const pcapReader: PcapReader = new PcapReader({filename: capture.temporaryFilename, watch: true})
    pcapReader.on('packet', (info): void => {
        console.log('packet', info.index, `${info.length} bytes`)
    })

    await capture.start()
    await pcapReader.start()
    console.log('started, capturing for 10s ...')
    await sleep(10000)

    console.time('pause')
    await capture.pause()
    console.timeEnd('pause')
    console.log(`captured ${capture.count} packets, pausing 5s ...`)
    await sleep(5000)

    console.time('resume')
    await capture.resume()
    console.timeEnd('resume')
    console.log('resumed, capturing for 10s ...')
    await sleep(10000)

    console.time('stop')
    await capture.stop()
    console.timeEnd('stop')
    console.log(`total captured: ${capture.count} packets`)

    await pcapReader.stop()
    await capture.dispose()
    console.log('disposed, done')
    process.exit(0)
})().catch((error: Error): void => {
    console.error('capture integration test failed:', error)
    process.exit(1)
})
