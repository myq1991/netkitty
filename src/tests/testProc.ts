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
    setInterval(() => {
        client.notify('testData', 'Now:', Date.now(), 'Random:', Math.random())
    }, 1)
    setTimeout(() => {
        process.exit()
    }, 60000)
})
