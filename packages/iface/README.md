<p align="center">
  <img src="https://raw.githubusercontent.com/myq1991/netkitty/main/assets/NetKittyLogo.webp" alt="NetKitty" width="180">
</p>

# @netkitty/iface

Read-only network interface enumeration — a small native addon that lists **every** interface on the
host, including the ones Node's own `os.networkInterfaces()` quietly hides: administratively-down
interfaces and interfaces that have no IP address yet. Each entry carries MAC, IPv4/IPv6 addresses,
up state, MTU, an adapter description, and per-interface received/transmitted byte, packet, error and
drop counters.

> 中文文档见 [README.zh-CN.md](./README.zh-CN.md)。

The addon speaks only to the operating system's own APIs — `getifaddrs` on Linux and macOS,
`GetAdaptersAddresses` plus `GetIfEntry2` on Windows. It does **not** link or load libpcap/Npcap and
has no external runtime dependency, so it is far easier to install than a capture-based package.

## Install

```bash
npm i @netkitty/iface
# or use the aggregate package: import {list} from 'netkitty/iface'
```

The native addon is compiled from source on your machine at install time (node-gyp). No prebuilt
binaries are published. Building needs only a C/C++ toolchain and Python — no libpcap, no Npcap SDK,
nothing to download.

## Quick start

```ts
import {list} from '@netkitty/iface'

for (const iface of list()) {
  console.log(iface.name, iface.mac, iface.up ? 'up' : 'down', `mtu=${iface.mtu}`)
  for (const addr of iface.addresses) {
    console.log('  ', addr.family, addr.address, addr.netmask)
  }
  console.log('   rx', iface.rx.bytes, 'bytes /', iface.rx.packets, 'packets')
  console.log('   tx', iface.tx.bytes, 'bytes /', iface.tx.packets, 'packets')
}
```

`list()` is synchronous and returns a snapshot of all interfaces, sorted by `name`, with every MAC
lower-cased. Call it again whenever you want fresh counters.

## Shape

```ts
interface INetworkInterfaceInfo {
  name: string                         // OS interface name; the adapter friendly name on Windows
  mac: string                          // lower-case xx:xx:xx:xx:xx:xx, or '' when there is no hardware address
  up: boolean                          // administratively up — down interfaces are still listed (up: false)
  mtu: number
  addresses: INetworkInterfaceAddress[]
  rx: INetworkInterfaceCounters        // received counters since boot
  tx: INetworkInterfaceCounters        // transmitted counters since boot
  description: string                  // adapter description on Windows; empty on POSIX
}

interface INetworkInterfaceAddress {
  family: 'ipv4' | 'ipv6'
  address: string
  netmask: string                      // IPv4: dotted mask (255.255.255.0). IPv6: mask, or /prefix on Windows
}

interface INetworkInterfaceCounters {
  bytes: number
  packets: number
  errors: number
  dropped: number
}
```

## Key ideas

### Why a native addon

Node's built-in `os.networkInterfaces()` only reports interfaces that currently have an IP address
bound, and gives you nothing about link state, MTU or traffic counters. This package goes to the OS
directly, so it can list:

- interfaces that are administratively **down** (`up: false`),
- interfaces with **no IP address** at all,
- the **up** flag, **MTU**, adapter **description**, and full **rx/tx** byte, packet, error and drop
  counters for each interface.

That makes it a better fit for a device picker or a link-status dashboard, where you want the whole
inventory rather than just the addressable subset.

### Not the same as pcap capture devices

Interface enumeration here is a plain OS inventory. It is a different thing from the capture-device
list a capture package obtains from libpcap/Npcap: this addon needs no capture library and no elevated
privileges to enumerate, and it reports link/stat metadata that a pcap device list does not.

### Cross-platform, OS APIs only

- **Linux / macOS**: `getifaddrs` walks every interface; MAC comes from `AF_PACKET` / `AF_LINK`
  entries. On macOS, MTU and counters come from the link-level `if_data`; on Linux they are read from
  `/sys/class/net/<iface>/…` (robust across glibc and musl).
- **Windows**: `GetAdaptersAddresses` supplies names, addresses, MTU and the friendly description,
  and `GetIfEntry2` supplies 64-bit octet/packet counters.

### Read-only, by design

This first release only enumerates and queries interfaces — it does not bring links up or down or
change any configuration.
