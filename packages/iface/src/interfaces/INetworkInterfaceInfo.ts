/** One IP address bound to an interface, with its address family and netmask. */
export interface INetworkInterfaceAddress {
    family: 'ipv4' | 'ipv6'
    address: string
    /** IPv4: dotted netmask (e.g. 255.255.255.0). IPv6: netmask, or `/prefix` on Windows. */
    netmask: string
}

/** Cumulative traffic counters for one direction of an interface (totals since boot). */
export interface INetworkInterfaceCounters {
    bytes: number
    packets: number
    errors: number
    dropped: number
}

/** Full description of one network interface: name, hardware address, state, MTU, addresses and counters. */
export interface INetworkInterfaceInfo {
    /** OS interface name — a human name on Windows (adapter friendly name), e.g. `eth0` / `en0` / `Ethernet`. */
    name: string
    /** Lower-case `xx:xx:xx:xx:xx:xx`, or empty when the interface has no hardware address. */
    mac: string
    /** Administratively up. Unlike `os.networkInterfaces()`, down interfaces are still listed (with `up: false`). */
    up: boolean
    mtu: number
    addresses: INetworkInterfaceAddress[]
    /** Received counters since boot. */
    rx: INetworkInterfaceCounters
    /** Transmitted counters since boot. */
    tx: INetworkInterfaceCounters
    /** Adapter description (Windows). Empty on POSIX. */
    description: string
}
