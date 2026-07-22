import {GetIfaceBinding} from './GetIfaceBinding'
import {INetworkInterfaceInfo} from './interfaces/INetworkInterfaceInfo'

/**
 * List every network interface — including administratively-down ones and interfaces without an IP
 * address (which `os.networkInterfaces()` omits) — with MAC, IPv4/IPv6 addresses, MTU, up state and
 * per-interface tx/rx counters. MAC is lower-cased and the result is sorted by name.
 */
export function list(): INetworkInterfaceInfo[] {
    return GetIfaceBinding()
        .list()
        .map((iface: INetworkInterfaceInfo): INetworkInterfaceInfo => ({...iface, mac: iface.mac.toLowerCase()}))
        .sort((a: INetworkInterfaceInfo, b: INetworkInterfaceInfo): number => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0))
}
