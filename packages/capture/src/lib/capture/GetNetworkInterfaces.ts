import {INetworkInterface} from './interfaces/INetworkInterface'
import {GetCaptureBinding} from './lib/GetCaptureBinding'
import sortArray from 'sort-array'

/**
 * Get network interfaces
 * @constructor
 */
export function GetNetworkInterfaces(): INetworkInterface[] {
    const ifaces: INetworkInterface[] = GetCaptureBinding().GetNetworkInterfaces()
    return sortArray(ifaces.map((iface: INetworkInterface): INetworkInterface => ({
        name: iface.name,
        mac: iface.mac.toLowerCase()
    })), {
        by: 'name',
        order: 'asc'
    })
}
