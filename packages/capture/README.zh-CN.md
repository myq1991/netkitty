# @netkitty/capture

基于原生插件的实时网络抓包,底层用 **libpcap(macOS/Linux)/ Npcap(Windows)**。对外的 `Capture` 类
**从不在主进程里直接碰原生绑定**:一个共享的宿主进程为每路抓包各开一条原生抓包线程,把每一个包通过命名
管道 IPC 通道回传给主进程。这样即使某一路抓包出问题、或者原生代码崩溃,也不会把整个应用一起拖垮。每个包
在到达时还会同步写进一个临时 pcap 文件里,`saveTo()` 再把这个文件拷出去。

> English docs: [README.md](./README.md)

## 安装

```bash
npm i @netkitty/capture
# 或者用聚合包:import ... from 'netkitty/capture'
```

本包带有原生插件。**项目绝不发布预编译二进制**——插件会在你本机安装时用 node-gyp 从源码现场编译
(`gypfile: true`)。因此你需要一套可用的 C/C++ 编译工具链,以及 pcap 的开发头文件:

- **macOS**:安装 Xcode 命令行工具(系统自带 libpcap)。
- **Linux**:一个编译器,外加 `libpcap-dev`(Debian/Ubuntu)或 `libpcap-devel`(RHEL/Fedora)。
- **Windows**:先装好 [Npcap](https://npcap.com/);插件在运行时动态加载 `wpcap.dll`,所以编译只需要
  头文件,不会打包任何 `.node`/`.lib`。

如果你只想列出网卡(不抓包,也就不用操心运行时的原生编译),可以看 [`@netkitty/iface`](../iface)。

## 快速上手

```ts
import {GetNetworkInterfaces, Capture} from '@netkitty/capture'

// 1. 选一块要抓包的网卡
const interfaces = GetNetworkInterfaces()          // [{name, mac}, ...],按 name 排序
const device = interfaces[0].name

// 2. 创建一路抓包
const capture = new Capture({
    device: device,                                // 必填:来自 GetNetworkInterfaces() 的网卡名
    filter: 'tcp port 443',                         // 可选:一条 BPF 过滤表达式
    emit: 'full'                                    // 可选:'full'(默认)| 'metadata'
})

// 3. 监听包
capture.on('packet', info => {
    console.log(info.index, info.length, info.seconds)   // 每个包都会带上元信息
})
capture.on('rawPacket', (index, packet, seconds, microseconds) => {
    // packet:base64 编码的原始字节(只在 'full' 模式下触发)
})
capture.on('error', err => console.error(err))     // 宿主进程崩溃会从这里冒出来

// 4. 运行
await capture.start()
// ...抓一段时间...
await capture.saveTo('/path/to/out.pcap')          // 把累积下来的 pcap 拷出去
await capture.stop()
await capture.dispose()                            // 停止,并释放这路会话和临时文件
```

## 构造选项(`ICaptureOptions`)

| 字段 | 类型 | 是否必填 | 说明 |
| --- | --- | --- | --- |
| `device` | `string` | 是 | 网卡名,取自 `GetNetworkInterfaces()`。 |
| `filter` | `string` | 否 | BPF 过滤表达式(tcpdump 语法),比如 `'udp and port 53'`。留空表示全抓。 |
| `emit` | `CaptureEmitMode` | 否 | `'full'`(默认)或 `'metadata'`,见下文。 |
| `tmpDir` | `string` | 否 | 临时 pcap 文件所在目录,默认是 `<系统临时目录>/netkitty-tmp`。 |
| `temporaryFilename` | `string` | 否 | 临时 pcap 文件的完整路径,默认由网卡名和 `tmpDir` 推导得出。 |
| `workerModule` | `string` | 否 | 自定义宿主 worker 模块路径(进阶用法;会替换内置模块,并跳过网卡校验)。 |

## 方法与事件

`Capture` 继承自 `EventEmitter`。所有生命周期方法都是异步的,可以依次 await:

- `start(): Promise<void>` —— 开始抓包(若处于暂停则恢复)。
- `stop(): Promise<void>` —— 停止抓包,并等宿主把已见到的包全部落盘。
- `pause(): Promise<void>` —— 停掉原生抓包但保留会话,之后 `resume()`/`start()` 可接着来。
- `resume(): Promise<void>` —— 继续一路已暂停的抓包。
- `setFilter(filter: string): Promise<void>` —— 更换 BPF 过滤器(正在运行则实时生效,否则下次 start 时生效)。
- `saveTo(destination: string): Promise<void>` —— 把累积下来的临时 pcap 文件拷到 `destination`。
- `dispose(): Promise<void>` —— 停止、拆掉会话,并删除临时文件。

只读属性:`filter`、`temporaryFilename`、`count`(到目前为止见到的包数)。

事件:

- `packet(info: IPcapPacketInfo)` —— **每一个**抓到的包都会触发,两种模式下都有。`info` 里带着 `index`、
  字节 `offset`/`length`、pcap 记录的各段偏移,以及时间戳(`seconds`/`microseconds`/`nanoseconds`)。
- `rawPacket(index: number, packet: string, seconds: number, microseconds: number)` —— 只在 `'full'`
  模式下触发;`packet` 是原始字节的 base64 编码。
- `error(error: Error)` —— 宿主进程崩溃了。它会被自动重新拉起,并把所有活动会话原样重建,所以抓包会继续
  进行;这个事件只是通知你崩溃发生过。

## 投递模式(`CaptureEmitMode`)

- **`'full'`**(默认)—— 每个包既带元信息,**也带**原始字节(`rawPacket`)。向后兼容,适合在内存里直接解码。
- **`'metadata'`** —— 只带元信息。字节留在磁盘上的 pcap 文件里,**不会**跨 IPC 边界传回来,从而省掉逐包的
  base64 编码和绝大部分负载。适合那种只打算事后看文件(通过 `saveTo()`)的长时间、高速率抓包;此模式下
  `rawPacket` 不会触发。

## 架构

主进程里只保留一些记账状态。第一次 `start()` 时,会 fork 出**一个共享的宿主进程**(用 `child_process.fork`,
在 Electron 里则用 `utilityProcess.fork`),每一个 `Capture` 都会用一个唯一 id 向它注册一路会话。宿主负责
驱动原生的 `libpcap`/`Npcap` 绑定——每路会话一条原生抓包线程——把每个包写进该会话的临时 pcap 文件,再打上
会话 id,通过同一条多路复用的命名管道通道回传。

把多路抓包收拢进一个进程(而不是每路各开一个 worker),正是多网卡抓包时省资源的关键。万一宿主进程意外挂掉,
它会被重新拉起,所有活动会话都会被重建并重新启动;同时通过 `error` 事件通知各自的持有者。当最后一路会话被
dispose 掉时,宿主进程随之关闭,不留残余。

## 平台与权限

- **macOS/Linux** 链接 **libpcap**;**Windows** 用 **Npcap**(运行时动态加载 `wpcap.dll`)。
- 在实时网卡上抓包通常需要**较高权限**——以 `root`/管理员身份运行,或授予等价能力(比如 Linux 上的
  `cap_net_raw`、BPF 设备权限,或 Npcap 的"仅限管理员"设置)。网卡枚举和过滤同样遵循你所在平台上 libpcap
  与 Npcap 的既有规则。

作为项目铁律,**netkitty 绝不发布预编译的原生二进制**:原生插件一律在安装时于本地从源码编译。
