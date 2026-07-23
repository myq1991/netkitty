import {ReplayDeviceNotFoundError} from './errors'

/**
 * Best-effort device pre-check. If @netkitty/iface is installed, verify the named interface exists and
 * throw a helpful error (listing what is available) when it does not. If @netkitty/iface is absent, the
 * check is silently skipped — the native send backend will still report a clear error on start.
 */
export function validateDevice(device: string): void {
    let names: string[] | null = null
    try {
        // eslint-disable-next-line @typescript-eslint/no-require-imports
        const iface: {list: () => {name: string}[]} = require('@netkitty/iface')
        names = iface.list().map((i: {name: string}): string => i.name)
    } catch {
        //@netkitty/iface not installed — skip the pre-check.
        return
    }
    if (names && !names.includes(device)) {
        throw new ReplayDeviceNotFoundError(`network interface "${device}" not found. Available interfaces: ${names.join(', ')}`)
    }
}
