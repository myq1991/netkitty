<p align="center">
  <img src="https://raw.githubusercontent.com/myq1991/netkitty/main/assets/NetKittyLogo.webp" alt="NetKitty" width="180">
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/@netkitty/iface"><img src="https://img.shields.io/npm/v/@netkitty/iface?style=flat-square&labelColor=162032&color=2979ff&logo=npm&logoColor=white" alt="npm version"></a>
  <a href="https://www.npmjs.com/package/@netkitty/iface"><img src="https://img.shields.io/npm/dm/@netkitty/iface?style=flat-square&labelColor=162032&color=22c55e&logo=npm&logoColor=white" alt="npm downloads"></a>
  <a href="https://github.com/myq1991/netkitty/blob/main/LICENSE"><img src="https://img.shields.io/npm/l/@netkitty/iface?style=flat-square&labelColor=162032&color=2979ff" alt="license"></a>
</p>

# @netkitty/iface

只读的网络接口枚举——一个小巧的原生插件,能列出主机上的**每一个**接口,包括 Node 自带的
`os.networkInterfaces()` 会悄悄漏掉的那些:处于管理性关闭状态的接口,以及还没有分配 IP 地址的接口。
每一条记录都带有 MAC、IPv4/IPv6 地址、up 状态、MTU、网卡描述,以及该接口收发的字节数、包数、错误数和
丢弃数。

> English docs: [README.md](./README.md)

这个插件只调用操作系统自己的接口——Linux 和 macOS 上用 `getifaddrs`,Windows 上用
`GetAdaptersAddresses` 加 `GetIfEntry2`。它**不链接、也不加载 libpcap/Npcap**,没有任何外部运行时
依赖,所以比抓包类的包好装得多。

## 安装

```bash
npm i @netkitty/iface
# 或者用聚合包:import {list} from 'netkitty/iface'
```

原生插件会在安装时于你本机从源码编译(node-gyp),项目不发布任何预编译二进制。编译只需要一套 C/C++
工具链和 Python,不需要 libpcap,不需要 Npcap SDK,也没有任何要额外下载的东西。

## 快速上手

```ts
import {list} from '@netkitty/iface'

for (const iface of list()) {
  console.log(iface.name, iface.mac, iface.up ? 'up' : 'down', `mtu=${iface.mtu}`)
  for (const addr of iface.addresses) {
    console.log('  ', addr.family, addr.address, addr.netmask)
  }
  console.log('   rx', iface.rx.bytes, '字节 /', iface.rx.packets, '包')
  console.log('   tx', iface.tx.bytes, '字节 /', iface.tx.packets, '包')
}
```

`list()` 是同步的,返回一份所有接口的快照,按 `name` 排序,并且每个 MAC 都转成了小写。想拿到最新的
计数,再调一次即可。

## 数据结构

```ts
interface INetworkInterfaceInfo {
  name: string                         // 操作系统里的接口名;Windows 上是网卡的友好名称
  mac: string                          // 小写的 xx:xx:xx:xx:xx:xx,没有硬件地址时为空字符串
  up: boolean                          // 是否管理性开启——关闭的接口也会列出(up 为 false)
  mtu: number
  addresses: INetworkInterfaceAddress[]
  rx: INetworkInterfaceCounters        // 开机以来的接收计数
  tx: INetworkInterfaceCounters        // 开机以来的发送计数
  description: string                  // Windows 上是网卡描述;POSIX 上为空
}

interface INetworkInterfaceAddress {
  family: 'ipv4' | 'ipv6'
  address: string
  netmask: string                      // IPv4:点分掩码(255.255.255.0)。IPv6:掩码,Windows 上是 /前缀长度
}

interface INetworkInterfaceCounters {
  bytes: number
  packets: number
  errors: number
  dropped: number
}
```

## 关键概念

### 为什么要用原生插件

Node 自带的 `os.networkInterfaces()` 只会报告当前绑定了 IP 地址的接口,而且不告诉你链路状态、MTU
或流量计数。这个包直接向操作系统查询,因此能列出:

- 处于管理性**关闭**状态的接口(`up` 为 `false`),
- 完全**没有 IP 地址**的接口,
- 每个接口的 **up** 标志、**MTU**、网卡**描述**,以及完整的 **rx/tx** 字节数、包数、错误数和丢弃数。

这让它更适合做设备选择器或链路状态面板——你要的是整份清单,而不只是有地址的那一部分。

### 和 pcap 抓包设备不是一回事

这里的接口枚举是一份纯粹的操作系统清单,和抓包类包通过 libpcap/Npcap 拿到的抓包设备列表是两码事:
这个插件枚举时既不需要抓包库,也不需要提升权限,而且它给出的链路和统计信息是 pcap 设备列表所没有的。

### 跨平台,只用系统接口

- **Linux / macOS**:用 `getifaddrs` 遍历每一个接口;MAC 取自 `AF_PACKET` / `AF_LINK` 记录。
  在 macOS 上,MTU 和计数取自链路层的 `if_data`;在 Linux 上则从 `/sys/class/net/<接口名>/…`
  读取(对 glibc 和 musl 都稳妥)。
- **Windows**:`GetAdaptersAddresses` 提供名称、地址、MTU 和网卡的友好描述,`GetIfEntry2` 提供
  64 位的字节/包计数。

### 设计上就是只读的

这一期功能只做枚举和查询,不会拉起或关闭链路,也不会改动任何配置。
