import {GetNetworkInterfaces} from './lib/GetNetworkInterfaces'
import {INetworkInterface} from './interfaces/INetworkInterface'

export class Capture {

    protected readonly device: string

    /**
     * Get available network devices
     */
    public static get availableDevices(): INetworkInterface[] {
        return GetNetworkInterfaces()
    }

    constructor(device: string) {
        if (!Capture.availableDevices.filter((availableDevice: INetworkInterface): boolean => availableDevice.name === device).length) throw new Error(`Device ${device} not found`)
        this.device = device
    }
}
