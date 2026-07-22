import {GetBinding} from './GetBinding'
import path from 'node:path'
import {existsSync} from 'node:fs'
import {INetworkInterfaceInfo} from './interfaces/INetworkInterfaceInfo'

export interface IIfaceBinding {
    list(): INetworkInterfaceInfo[]
}

//Walk up from this module to find bindings/netkitty_iface.node — robust whether loaded from dist/ or
//dist-test/ (whose extra rootDir level would break a fixed relative path).
function resolveBindingPath(): string {
    let dir: string = __dirname
    for (let i: number = 0; i < 6; i++) {
        const candidate: string = path.join(dir, 'bindings', 'netkitty_iface.node')
        if (existsSync(candidate)) return candidate
        dir = path.dirname(dir)
    }
    return path.resolve(__dirname, '../../bindings/netkitty_iface.node')
}

let binding: IIfaceBinding | null = null

export function GetIfaceBinding(): IIfaceBinding {
    if (!binding) {
        binding = GetBinding(resolveBindingPath()) as IIfaceBinding
    }
    return binding
}
