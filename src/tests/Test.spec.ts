import {PipeServer} from '../lib/pipe/PipeServer'
import {PipeClient} from '../lib/pipe/PipeClient'
import {fork} from 'node:child_process'
import path from 'node:path'

// const bc = new BindingCapture({iface: 'en0'})
// bc.on('data', console.log)
// bc.start()

// console.log(GetNetworkInterfaces())

// new Capture({
//     device:'en0'
// })

const server = new PipeServer({
    actions: {
        foo: async () => {
            return {
                res: 'bar',
                time: Date.now()
            }
        }
    }
})
server.on('connect', async socket => {
    setInterval(()=>{
       socket.notify('testData1','oh?!!!!!')
    },0)
    socket.on('disconnect', () => {
        console.log('close!!!!')
    })
    .on('testData', console.log)

    console.log(await socket.invoke('hello', 'myq1991'))
})
const cp = fork(path.resolve(__dirname, './testProc'), {env: {socketPath: server.socketPath}})

