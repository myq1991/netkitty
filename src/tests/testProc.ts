import {PipeClient} from '../lib/pipe/PipeClient'

const client = new PipeClient({
    id: 'test',
    socketPath: process.env.socketPath!,
    actions: {
        hello: async (name: string) => {
            return {
                name: name ? name : 'unknown',
                time: Date.now()
            }
        }
    }
})
client.once('ready', () => {
    setInterval(async () => {
        client.notify('testData', 'Now:', Date.now(), 'Random:', Math.random())
        console.log(await client.invoke('foo'))
    }, 0)
    setTimeout(() => {
        process.exit()
    }, 60000)
}).on('testData1', console.log)
