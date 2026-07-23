import {GetBinding} from '../GetBinding'
import path from 'node:path'
import * as os from 'node:os'
import {CaptureNpcapLoadError} from '../errors/CaptureNpcapLoadError'

let binding: any

export function GetCaptureBinding(): any {
    if (!binding) {
        binding = GetBinding(path.resolve(__dirname, '../../../../bindings/netkitty_capture.node'))
        if (os.platform() === 'win32') {
            const prepareResult: boolean = binding.Prepare()
            if (!prepareResult) throw new CaptureNpcapLoadError('Npcap loading failed. Please confirm whether Npcap has been installed.')
        }
    }
    return binding
}
