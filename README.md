# NetKitty

miaowu~

NetKitty 是一个 Node.js / Electron 网络工具包：实时抓包（基于 libpcap / Npcap 的原生扩展）、PCAP 文件读写解析、以及一套 **Schema 驱动的网络协议编解码器**。内置以太网、VLAN、ARP、IPv4/IPv6、TCP/UDP、ICMP/ICMPv6、TLS 各记录类型，以及电力行业协议 GOOSE、IEC 61850-9-2 采样值（SV）与 IEC 60870-5-104。

## 模块

| 子路径导出 | 内容 |
| --- | --- |
| `netkitty/network` | `Capture` 实时抓包、`GetNetworkInterfaces` 网卡枚举 |
| `netkitty/pcap` | `PcapReader` / `PcapWriter` / `PcapParser` 及 PCAP 生成函数（读取支持经典 pcap 的大小端与微秒/纳秒变体、pcapng；`.cap` / tcpdump 产物即经典 pcap 格式） |
| `netkitty/codec` | `Codec` 编解码器、`BaseHeader` 协议基类、Schema 类型 |
| `netkitty/codec/header` | 全部内置协议头实现 |
| `netkitty/helper` | Buffer / Hex / 数值 / IP / BER 转换工具函数 |

```javascript
const {Codec} = require('netkitty/codec')

const codec = new Codec()
// 解码：Buffer → 结构化字段树（永不失败，未知数据落为 raw）
const layers = await codec.decode(packetBuffer)
// => [{id: 'eth', name: 'Ethernet II', data: {...}, errors: []}, {id: 'ipv4', ...}, ...]

// 编码：有序的 {id, data} 列表 → 报文 Buffer
const {packet, errors} = await codec.encode([
    {id: 'eth', data: {...}},
    {id: 'ipv4', data: {...}},
    {id: 'tcp', data: {...}}
])
```

---

## 设计思路

NetKitty 编解码器的定位不是"又一个 dissector 库"，而是**为图形化报文编辑器（可编程的 Wireshark）倒推出来的架构**。它的全部设计决策都围绕一个核心问题：如何让"报文的语法"和"报文的编辑界面"成为同一个事实来源。

### 1. 核心理念：可执行的协议 Schema，一份定义四种角色

每个协议头是一个继承 `BaseHeader` 的类，其唯一的核心资产是一份 `SCHEMA` —— 一个 JSON Schema Draft-7 的变体（`ProtocolFieldJSONSchema`）。这份 Schema 同时承担四种角色：

1. **结构定义** —— `properties` 的嵌套即字段树，树形结构同时决定编解码的遍历顺序（解码先序、编码后序）；
2. **编解码逻辑载体** —— 每个字段上内嵌 `decode` / `encode` 闭包，闭包捕获协议类实例的 `this`，通过 `readBytes` / `writeBytes` / `readBits` / `writeBits` 原语操作共享的报文 Buffer。**Schema 既是数据，也是程序**；
3. **输入校验** —— 编码入口用 Ajv 直接编译这份 Schema 校验用户输入。`useDefaults: true` 让 Schema 兼任"报文模板"（缺省字段自动补默认值），`coerceTypes: true` 面向 GUI 表单输入（"255" 自动转数字）——这是一种面向表单而非严格 API 的宽容校验姿态；
4. **UI 元数据** —— 在标准 JSON Schema 之上扩展了 `label`（字段显示名）、`hidden`（GUI 不渲染的判别器字段）、`contentEncoding`（HEX / MAC / IPv4 / BIGINT 等，声明字符串实际承载的内容格式），配合标准的 `enum` / `minimum` / `maximum` / `anyOf` + `const`（tagged-union 变体判别），前端拿到 Schema 即可渲染出 Wireshark 式的逐字段编辑表单。

四种角色共享一个定义，从根本上杜绝了"改了字节布局忘了改表单/校验"的漂移问题——这是典型的**单一事实来源（Single Source of Truth）**思想。

### 2. 一行代码切开两个世界：`JSON.parse(JSON.stringify(SCHEMA))`

Schema 中的 `decode` / `encode` 是函数，无法也不应暴露给前端。`PROTOCOL_SCHEMA` getter 通过一次 JSON 序列化往返，**利用"JSON 序列化天然丢弃函数"这一特性**，把可执行部分剥离，剩下纯声明部分安全地交给外部消费。这条天然分界线干净地划分了两个世界：

- **声明式外壳**（可序列化）：类型、范围、枚举、默认值、变体判别、字段层级、显示元数据 —— 校验和 UI 免费获得；
- **命令式内核**（留在运行时）：字节偏移、位域提取、TLV/BER 变长解析、跨字段依赖回填、语义换算（如 IPv4 `hdrLen × 4`）。

真实网络协议充满上下文相关文法（长度由别的字段决定、字段存在性由标志位决定、校验和依赖尚未生成的字节），纯声明式方案（如 Kaitai Struct）为此不得不在声明里嵌入表达式语言，最终仍是"伪装成数据的代码"，且几乎都放弃了编码方向。NetKitty 的取舍是诚实的：**能声明的交给 Schema，本质上是过程的留给宿主语言闭包**——不自造外部 DSL，而是把 TypeScript 对象字面量 + 闭包当作**寄生在 JS 运行时的内部 DSL**，省掉编译器和代码生成，换来完整的图灵完备宿主能力（BER-TLV、伪首部校验和都能现写），同时白拿 Ajv 工业级校验器、标准 JSON Schema 的前端生态和 TypeScript 的类型检查。

### 3. 解码管线：链式自识别 + 永不失败

解码用一张**分发表**（构造期一次性建好）在层间做 O(1) 选择：每个协议声明自己的挂载点 `matchKeys`（如 IPv4 的 `['ethertype:0800']`、TCP 的 `['ipproto:6']`），表把"解复用键 → 协议"映射起来。解码时读出上一层的解复用字段值直接查表命中下一层——以太网的 `etherType` 归入 `ethertype:` 命名空间，IPv4 的 `protocol` 与 IPv6 的 `nxt` 归入同一个 `ipproto:` 命名空间（因此 TCP 只登记一次 `ipproto:6`，在 IPv4 和 IPv6 之上都能解出）。这符合网络栈的本质：协议归属由上层的解复用字段决定。

**关键在于分发表不编码任何层序**——它只是"解复用值 → 协议"的电话簿，具体层序完全由报文运行时实际携带的解复用值决定。所以缺层、增层、造错包都被自然处理：同一个 IPv6 报文，`nxt=6` 就直接解出 TCP、`nxt=0` 就先解 HopByHop 再看它的 `nxt`；解复用值未登记则落 `RawData` 兜底，值被伪造则按它声称的协议尽力解。

选择顺序是三级：分发表 → **内容启发式候选**（未声明 `matchKeys`、需自检字节的协议：TLS、IEC104、以太网隧道，以及未声明键的第三方自定义协议）→ `RawData` 显式兜底。`RawData` 不在表里而是最终兜底，因此**解码永不失败**，且新增自定义协议不再被兜底项遮蔽（修复了旧的"新协议解码不可达"缺陷）。推进模型是一个全局游标（`startPos`）：每层解码后游标推进到 `endPos`，头长度由 `readBytes` 以"水位式"副作用增长（取实际触碰的最远字节），因此变长头（IPv4 options、TCP options、TLV 嵌套）无需预知长度。

### 4. 编码管线：按序拼装 + 自动扩容

编码输入是有序的 `{id, data}` 数组——调用方声明"这个包由哪些层组成"，`Codec` 按 id 找到协议类，Ajv 校验补默认值后逐层编码。Buffer 从空开始，`writeBytes` 越界时自动零填充扩容，写多少长多少，无需预计算包长。读写共用同一套"相对本头 `startPos`"的寻址，协议实现者只关心层内偏移，全局拼接由框架游标完成——这保证了**同一字段的 decode 和 encode 物理上并置、逻辑上对称**，服务于编辑器"解开一个包、改一个字段、重新编码发出去"的核心工作流。

### 5. 跨层依赖：两级 post handler 与 LIFO/FIFO 的方向哲学

校验和与长度字段是协议编码器的经典难题：IPv4 总长度依赖下游所有层的长度，TCP 校验和依赖 IP 伪首部且覆盖尚未定型的载荷。NetKitty 用**带优先级的延迟后处理器**从声明式流程中"逃逸"：

- **层内后处理**（`postSelfEncode/Decode`）：本头编解码完立即执行，解决层内回填（如 TCP `hdrLen` 需等 options 写完）；
- **包级后处理**（`postPacketEncode/Decode`）：全包完成后统一执行，且**编码按 LIFO、解码按 FIFO**。

这个方向约定不是随意的：编码时依赖方向是"外层依赖内层的最终形态"（IP 总长度要累加所有下游、TCP 校验和要等载荷字节定型），所以最内层先固化、逐层向外结账；解码时相反，内层语义依赖外层已解出的上下文（TCP 伪首部校验需要 IPv4 的源/目的地址），自然先进先出。本质上是**把"字段值依赖图"的拓扑排序，工程化为方向约定 + 优先级**的简化方案。

### 6. FlexibleObject：为 GUI 设计的路径追踪数据容器

字段值不存普通对象，而是存入 Proxy 实现的 `FlexibleObject`：任意深度的属性访问永不抛 TypeError（未知节点惰性创建），`getValue(defaultValue, onUndefinedCallback)` 把"取值、兜底、错误定位"合成一个原子操作——回调收到的是精确的点分字段路径（含数组下标，如 `options[3].kind`）。这个容器同时承担**数据、Schema 路径映射、错误坐标系**三职：每条编解码错误都能直接定位到 UI 上的具体输入框。

### 7. 容错哲学：错误累积 + 值钳制，畸形包是一等公民

作为报文构造/剖析工具，NetKitty 把畸形数据当作正常输入而非异常：解码遇到非法值（如 IPv4 `version ≠ 4`）记录错误照常解完；编码遇到越界值先记录错误再钳制到边界（65536 → 记错并钳为 65535）继续编码。抛异常是"全有或全无"，错误累积则输出"尽力而为的结果 + 带字段路径的完整问题清单"——解析恶意流量不丢弃剩余可读信息，构造测试包允许用户故意填非法值，且无论输入多离谱，产出的始终是结构合法、字节宽度正确的 Buffer。唯一的快速失败点是编码入口的 Ajv 结构校验（数据形状根本不对时）。

### 8. 业界坐标系中的位置

把主流方案放在"声明式 ↔ 命令式"光谱上：

| 方案 | 位置 | 特点 |
| --- | --- | --- |
| Kaitai Struct / protobuf IDL | 纯声明式 | 外部 DSL + 代码生成，Kaitai 长于读、弱于写 |
| Scapy / construct / binary-parser | 声明式为主 | 字段类型对象拼装，跨字段逻辑靠有限组合子 |
| **NetKitty** | **声明式外壳 + 命令式内核** | **Schema 四用，读写对称，面向 GUI** |
| Wireshark dissector | 纯命令式 | C 手写解析，字段元数据与逻辑分离，分发表调度 |

NetKitty 有两个业界方案不同时具备的独特点：**同一份 Schema 直接可供外部前端渲染可编辑表单**（Wireshark 的字段元数据只能喂它自己的 GUI，Scapy/construct 没有这个维度），以及**编解码天生双向对称**（多数解析器框架以"读"为中心）。代价同样明确：线性 `match()` 扫描 + `prevCodecModule` 隐式耦合，在协议数量爆炸或需要大规模第三方贡献时不如 Wireshark 的分发表；逐字段 async 闭包的执行模型也不适合线速高吞吐解析。

**一句话概括核心洞察：把协议定义本身变成"可执行的 UI Schema"——一份自描述结构同时承担解析器、校验器和表单描述符，让报文的语法和报文的编辑界面成为同一个事实。** 它不是在做更好的 dissector，而是把编解码器重新定义为"GUI 报文编辑器的可序列化后端模型"。

### 适用场景与边界

**最适合**：中等数量协议、需要双向读写 + 前端可视化编辑的场景——尤其是 GOOSE/SV 这类带大量枚举语义、需要工程师在 GUI 里逐字段改值重发的电力测试场景（Schema 即表单，价值最大化）。

**不适合**：高吞吐线速解析（执行模型开销大，性能远低于 Kaitai 生成码或 Wireshark C 实现）、协议数量极多的通用 dissector 平台、需要跨语言复用解析器的场景（闭包锁死在 JS 运行时）。

### 扩展协议

继承 `BaseHeader`，实现 `SCHEMA` / `id` / `name` / `nickname` / `match()`，即得到一个新协议编解码器。传入 `Codec` 构造函数时，与内置协议 `PROTOCOL_ID` 相同的实现会**覆盖**内置协议；新增内置协议需注册到 `src/lib/codec/PacketHeaders.ts`（注册顺序即 `match()` 的匹配优先级，`RawData` 恒为最后的兜底项）。

## 构建

```bash
npm run build:cpp        # 编译原生抓包扩展（需要 libpcap / Npcap 开发环境）
npm run build:js         # 编译 TypeScript
npm run rebuild          # 两者全量重建
npm test                 # 编译 TS 后运行全部单元测试（node:test，非交互，可进 CI）
npm run test:only        # 跳过编译直接运行单元测试
npm run test:integration # 抓包集成测试（需真实网卡与管理员权限）
```

单元测试基于真实抓包提取的样本（`src/tests/fixtures/`），核心断言是**往返测试**：decode → encode 必须逐字节还原原始报文。已知 bug 以 `todo` 标记记录在用例中，修复后摘除标记即为验收。

## License

MIT
