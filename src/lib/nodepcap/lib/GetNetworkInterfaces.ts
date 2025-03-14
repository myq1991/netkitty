import {INetworkInterface} from '../interfaces/INetworkInterface'
import {GetNodePcapBinding} from './GetNodePcapBinding'
import sortArray from 'sort-array'

/**
 * Get network interfaces
 * @constructor
 */
export function GetNetworkInterfaces(): INetworkInterface[] {
    const ifaces: INetworkInterface[] = GetNodePcapBinding().GetNetworkInterfaces()
    return sortArray(ifaces.map((iface: INetworkInterface): INetworkInterface => ({
        name: iface.name,
        mac: iface.mac.toLowerCase()
    })), {
        by: 'name',
        order: 'asc'
    })

}
