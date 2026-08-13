# Left4Proxy

> 说明: 本项目及其相关代码与(部分)文档由人工智能 (AI) 辅助设计与生成.  
> 虽经过一定的测试和代码审查, 但仍可能含有未发现的问题. 请谨慎使用.
> 
> 工具:
> Antigravity + Gemini 3.6 Flash (High) : 基础应用程序架构  
> Claude Code + DeepSeek V4 Flash (High, 0731) : 关键代码审查, STUN 打洞, 错误修复等.

Left4Proxy 是一套专为求生之路 2 (Left 4 Dead 2 / Source 引擎) 设计的专用网络代理与动态选路中间件.

系统主要解决内网穿透(如 frp / HAProxy)场景下客户端真实 IP 丢失, 局域网直连优化, STUN UDP 打洞以及 Source 引擎 loopback 地址绑定限制等问题.

> [!IMPORTANT]
>
> 该解决方案是用来解决玩家通过内网穿透时, 所有玩家只能连接到一个 IP 的问题. (匹配, 非 `connect` 命令).  
> 而且对部分玩家，流量经内网穿透绕一圈反而延迟更高.
>
> 其代理特性也注定了它基本上只能用于玩家间私下联机  
> 因为每位玩家都必须启动客户端才能连接到您的服务器
> 
> 该软件可能比我们想象的要脆弱 (即不保证它安全/绝对安全)  
> 大规模使用/用于公开游戏可能会使你的服务器暴露更多风险.

> [!TIP]
> Left4Proxy **不是** 通用代理软件. 也不是开箱即用软件. (您很可能需要找到适合您自己和兼顾朋友的配置)
> 
> Left4Proxy 客户端只接受一个 UDP 连接并 **只接受已识别的数据包模式** (如 《求生之路》发送的数据包)  
> 暂不确定是否适用于其它起源引擎游戏. 部分数据包 (如 A2S Query) 会经过 Left4Proxy 特殊处理.

## 核心特性

- **Source 引擎协议解析与过滤**：校验 `L4DP` 数据包魔法头及 Source 引擎 OOB / NetChannel 数据包结构, 避免中继无关数据包.
- **Proxy Protocol v2 支持**：服务端支持解析前置代理 (如 frpc / frps / HAProxy) 传入的 Proxy Protocol 报文, 提取客户端真实公网 IP 与端口.
- **动态端点发现与选路**: 客户端通过服务端广播的端点列表 (`public_ips`)，自动探测局域网 (LAN) 直连, 服务器中继和打洞线路, 并根据 RTT 延迟与网络类型完成无缝路由切换.
- **NAT 打洞直连**: 当代理服务端处于 NAT 后 (无端口映射, 仅靠 frp 中继暴露) 时, 双方尝试互打洞建立一条**不经过 frp 中继**的直接 UDP 通路. 如失败或 frp 中继网络更好则回落 frp.
- **离线探测与自动重连**: 针对 UDP 无连接特性, 引入应用层心跳探测机制. 服务端离线时客户端静默重试, 服务端恢复后自动连接.
- **L4D2 Loopback 绑定适配**: 客户端默认绑定至 `127.0.0.2:27015`, 规避 Source 引擎拒绝连接 `127.0.0.1` 本地环回地址的限制.

> 如果您使用内网穿透 (如 frpc) 且支持传递真实IP时, 非常建议启用 Proxy Protocol v2. 因为打洞需要真实 IP.  
> 不传递 IP 的情况下, 流量大概率会经过 LAN (同一局域网) 或 内网穿透中继.

## 架构与工作流程

1. **客户端接入**：客户端启动后连接指定的 Server 地址 (如 frp 穿透域名).
2. **握手与真实 IP 提取**：若开启 Proxy Protocol, 服务端将尝试解析来自代理/内网穿透的请求. 提取真实客户端 IP, 并在响应中带回服务端配置的所有候选 IP 列表 (`public_ips`).
3. **并行探测与路由选择**：客户端对所有候选 IP 进行并行 UDP 心跳探测测定 RTT 延迟. 优先选择局域网内网 IP (`PathLAN`), 其次按 RTT 选择最优的直连/中继候选。路径分为四类:
   - `PathLAN`: 同局域网直连 (最短路径, 避免房主同一局域网绕行)
   - `PathDirect`: 客户端直连到有公网 IP 的 Left4Proxy 服务器 (真直连, 无需打洞)
   - `PathPunch`: 客户端经打洞/端口映射直连到 NAT 后面的 Left4Proxy 服务器
   - `PathRelay`：客户端经内网穿透 (frp/HAProxy) 隧道中转  
   服务器在握手时根据"该连接是否走隧道 (PROXY)"和"服务器自身是否在 NAT 后"  
   判定路径类型随握手响应告知客户端  
   握手响应还会携带服务端的公网打洞端点 (`stun_server` 反射发现, 或用 `punch_addr` 手动指定)
4. **打洞直连**: 若服务端在 NAT 后且客户端目前只能走代理中继, 客户端会创建打洞套接字:  
   用公网 STUN 服务器反射出该套接字的公网端点, 通过中继把该端点告知服务端  
   服务端据此向客户端打洞 (打开自身 NAT 映射), 双方互发 STUN 探测  
   如果打洞成功且延迟更低, 则会直接直连服务端. 打洞失败或延迟更高将回退中继.
6. **报文代理转发**: 本地 L4D2 客户端（`127.0.0.2:27015`）发出的游戏数据包经 Left4Proxy 封装后发送至最优服务端/内网穿透候选节点，服务端解包并转发至实际 L4D2 目标服务器 (`x.x.x.x:27015`)

## 部署操作

1. 部署一个 L4D2 专用服务器. 端口保持 `27015`, ip 开放 `0.0.0.0`.
2. (可选) 部署内网穿透. 远程端口应等于 Left4Proxy 服务端的 `listen_addr` 端口 (默认 `27014`), 而不是 L4D2 的 27015;
   转发目标为 Left4Proxy 服务端. tcp+udp 同端口, 同远程对等. 若支持传递真实 IP, 在内网穿透上启用 Proxy Protocol v2 协议.
4. 部署 Left4Proxy Server. `public_ips` 内添加出口地址:  
   如果你的服务器和内网处于同一局域网. 添加内网 ip `192.168.x.x:27014`  
   如果你部署了单个或多个内网穿透. 添加外部内网穿透的 ip/域名和端口.  
   警告: 如果开启了 `proxy_protocol_v2`, 不要暴露给未开启此功能的内网穿透. 这可能会导致 IP 欺骗等问题.
5. 客户端打开 Left4Proxy Client, 在 `server_addrs` 中填内网穿透外部地址. 验证是否可连接  
   如果服务器侧还配置了内网 ip 且你和服务器在同一内网, 它应该会自动切换到内网 IP.
6. 启动 Left4Proxy 的服务器和客户端, 求生之路专用服务器和求生之路客户端. 客户端控制台输入 `connect 127.0.0.2` 测试正常连接.

> [!TIP]
> 提示: 您可以通过 `public_ips` 指定多个内网穿透地址以优化联机网络.
>
> 如果您的朋友正在使用校园网/共享NAT的小区网络. 且您自己的网络很好
> 您可以自己创建多条隧道. 选离他们近的(同省)节点而不是选离你们近的节点. (不再赘述运营商等)
> RTT可能会降低 5ms 或更高, 有的时候游戏延迟甚至能降低 100+ 毫秒. 待具体测试.

## 验证打洞直连

当代理服务端在 NAT 后且没有端口映射时, 玩家流量默认全部经 frp 中继绕行.  
开启打洞后，客户端会尝试与 NAT 后的服务端建立一条不经过 frp 的**直接** UDP 通路 (打洞失败如对称型 NAT 时自动回落中继).

验证步骤:

1. 服务端需可访问公网 UDP 3478（或自行指定 `stun_server`）。启动后确认日志出现 `[Server] Public endpoint discovered -> x.x.x.x:xxxxx`。
   - 若服务端有端口映射/固定公网端口，可直接在配置里设 `punch_addr: "公网IP:端口"` 跳过 STUN 反射。
2. 客户端在**与服务器不同的网络**（例如手机热点）启动。确认日志依次出现：
   - `Punch candidate created -> direct endpoint [...]`
   - `Punch socket public endpoint discovered -> [...]`
   - `PunchInit sent (my public endpoint ...) via candidate [...]`
   - `Punch path confirmed -> direct endpoint [...]`
   - `Active Route Switched -> Candidate: [...] | Mode: [Punch]`
3. 观察 frp 隧道流量下降（直连后不再经中继）。
4. 若某一方处于对称型 NAT，打洞失败，日志出现 `Punch to [...] failed (no direct path), staying on relay`，流量继续走中继——属预期行为。

## 与求生之路的 Matchmaking 配合使用

如果你让朋友都用 `connect` 带一堆人也没什么不便, 且你已经习惯切建图代码了, 切模式也滚瓜烂熟了.  
那这里不是为你准备的.

确保您已经完成了部署操作.

1. 确保求生之路服务器侧配置了 `net_public_adr` 为 `127.0.0.2` 或其它保留地址 (确认服务端本体未修改端口)
2. 前往控制台输入 `mm_dedicated_force_servers 127.0.0.2:27015` (需与上述地址一致, 含端口)  
   匹配最佳专用服务器前必输入, 否则会匹配不到.  
   如果不喜欢每次都输入, 去 `left4dead2/cfg` 目录下 创建/编辑 `autoexec.cfg`. 插入一行  
   `bind "F8" "mm_dedicated_force_servers 127.0.0.2:27015"`  
   可以改键位. 下次匹配前按一下这个键 (F8) 就自己改了
3. 确保求生之路服务器已启动, Left4Proxy 服务器已启动
5. 确保所有玩家均正确配置 Left4Proxy 客户端且开启并连接到了服务器. (共享配置文件其实就行了)
6. 与好友一起玩游戏 -> 创建新的大厅 -> 邀请好友 -> 确保 `mm_dedicated_force_servers` 值不为空 -> 选择目前最佳专用 -> 匹配.
7. 应该正常连接. 如果无法匹配:
   > (不是玩家连不上或掉线! 房主显示"无法匹配到最佳专用服务器 是否使用本地服务器")
   - 检查 `net_public_adr` 是否设置有误  
   - Left4Proxy 服务器无法访问本地求生之路服务器. (未正确配置)  
   - 房主(你)的 Left4Proxy 客户端掉了.

## 配置文件说明

### 服务端配置 (`config.server.yaml`)

```yaml
listen_addr: ":27014"
target_addr: "127.0.0.1:27015"
proxy_protocol_v2: true  # 配合 frp/HAProxy 传递真实客户端 IP 时开启
# 服务器是否在 NAT 后 (auto 自动检测 / true / false)，影响 Direct/Punch 判定
nat: "auto"
# 根据实际内网IP和内网穿透IP填
public_ips: []
# 公网 STUN 服务器 (打洞: 让 NAT 后的服务端反射出自己的公网端点)
stun_server: "stun.cloudflare.com:3478"
# 手动指定服务端公网打洞端点 (ip:port); 为空则用 stun_server 自动发现
punch_addr: ""
```

- `listen_addr`: 服务端 UDP 监听地址.
- `target_addr`: 实际 L4D2 服务器监听地址. (避免 Loopback 通常为LAN IP)
- `proxy_protocol_v2`: 是否开启 Proxy Protocol v1/v2 解析(配合 frp/HAProxy 使用)
- `nat`: 服务器是否在 NAT 后。`auto` 自动检测（看有没有公网接口 IP），可显式设 `true`/`false` 覆盖 (如云 VPS 只有内网 VPC 地址时). 这会决定服务端是否要自己打洞.
- `public_ips`: 服务端广播给客户端的候选节点地址列表 (包含局域网 IP 与公网域名/IP).
- `stun_server`: 打洞用的公网 STUN 服务器 (默认 `stun.cloudflare.com:3478`, 需可出站访问 UDP 3478). 服务端用它反射出自己的公网端点并广播给客户端.
- `punch_addr`: 手动指定服务端公网打洞端点 (`ip:port`). 有端口映射/固定公网端口时设置可跳过 STUN 反射; 留空则自动发现.

### 客户端配置 (`config.client.yaml`)

```yaml
server_addrs: # 支持备选
  - "内网穿透服务器地址:端口号"
listen_addr: "127.0.0.2:27015"
mode: "auto"
enable_lan: true
enable_punch: true
ping_interval: 3
stun_server: "stun.cloudflare.com:3478"
```

- `server_addrs`: 初始连接的服务端地址列表。
- `listen_addr`: 本地监听地址（默认 `127.0.0.2:27015`，Source 引擎拒绝连接 `127.0.0.1`，故使用其它环回地址）。
- `mode`: 路由模式，支持 `auto`（自动择优）、`direct-only`（仅直连，不走服务器中继）、`relay-only`（仅中转）。
- `enable_lan`: 是否启用局域网直连检测（同局域网时优先走 LAN，免绕公网）。
- `enable_punch`: 是否启用 STUN 打洞直连（服务端在 NAT 后时，为玩家打洞直连绕过 frp 中继；打洞失败自动回落中继）。
- `ping_interval`: 心跳探测间隔（秒）。
- `stun_server`: 打洞套接字反射公网端点所用的 STUN 服务器（默认 `stun.cloudflare.com:3478`）。

## 构建与运行

### 依赖环境

- Go 1.20 或更高版本

### 编译指令

```bash
# 编译 Linux 平台版本
go build -o bin/left4proxy-server ./cmd/server
go build -o bin/left4proxy-client ./cmd/client

# 交叉编译 Windows 平台版本
GOOS=windows GOARCH=amd64 go build -o bin/left4proxy-server.exe ./cmd/server
GOOS=windows GOARCH=amd64 go build -o bin/left4proxy-client.exe ./cmd/client
```

### 运行方式

```bash
# 启动服务端
./bin/left4proxy-server -c config.server.yaml

# 启动客户端
./bin/left4proxy-client -c config.client.yaml
```

## 许可证

本项目遵循 MIT 许可证。
