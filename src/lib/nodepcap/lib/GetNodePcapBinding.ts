import {GetBinding} from '../../GetBinding'
import path from 'node:path'
import * as os from 'node:os'

let binding: any

export function GetNodePcapBinding(): any {
    if (!binding) {
        binding = GetBinding(path.resolve(__dirname, '../../../../bindings/nodepcap/nodepcap.node'))
        if (os.platform() === 'win32') {
            const prepareResult: boolean = binding.Prepare()
            if (!prepareResult) throw new Error('Npcap loading failed. Please confirm whether Npcap has been installed.')
        }
    }
    return binding
}
