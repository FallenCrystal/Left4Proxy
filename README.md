# Left4Proxy

> 说明: 本项目及其相关代码与(部分)文档由人工智能 (AI) 辅助设计与生成.  
> 虽经过一定的测试和代码审查, 但仍可能含有未发现的问题. 请谨慎使用.
> 
> 工具:
> Antigravity + Gemini 3.6 Flash (High) : 基础应用程序架构  
> Claude Code + DeepSeek V4 Flash (High, 0731) : 关键代码审查, STUN 打洞, 错误修复等.

Left4Proxy 是一套专为求生之路 2 (Left 4 Dead 2 / Source 引擎) 设计的专用网络代理与动态选路中间件.

系统主要解决 frp 等 UDP 中继场景下的多入口选路、局域网直连优化、STUN UDP 打洞以及 Source 引擎 loopback 地址绑定限制等问题.

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

- **端到端认证与加密**：使用共享的 256-bit `.secret` 认证临时 X25519 握手，并为会话派生独立方向密钥；握手后的控制包与游戏数据全部使用 AES-256-GCM 加密，带序列号重放保护。旧版明文协议不会被接受。
- **不可伪造的 STUN 结果**：每个 STUN 请求使用独立的密码学随机 Transaction ID；只有在有效期内、从请求目标的精确 IP:端口返回且 Transaction ID 匹配的 Binding Response 才能更新公网端点。
- **Source 引擎协议解析与过滤**：校验 `L4DP` 数据包魔法头及 Source 引擎 OOB / NetChannel 数据包结构, 避免中继无关数据包.
- **动态端点发现与选路**: 客户端同时探测配置的中继入口 (`server_addrs`)、服务端认证后广播的直连地址 (`public_ips`) 与打洞线路，并根据 RTT 延迟与网络类型完成无缝路由切换.
- **NAT 打洞直连**: 当代理服务端处于 NAT 后 (无端口映射, 仅靠 frp 中继暴露) 时, 双方尝试互打洞建立一条**不经过 frp 中继**的直接 UDP 通路. 如失败或 frp 中继网络更好则回落 frp.
- **离线探测与自动重连**: 针对 UDP 无连接特性, 引入应用层心跳探测机制. 服务端离线时客户端静默重试, 服务端恢复后自动连接.
- **L4D2 Loopback 绑定适配**: 客户端默认绑定至 `127.0.0.2:27015`, 规避 Source 引擎拒绝连接 `127.0.0.1` 本地环回地址的限制.

## 架构与工作流程

1. **客户端接入**：客户端启动后连接指定的 Server 地址 (如 frp 穿透域名).
2. **认证握手与候选下发**：客户端使用 `.secret` 对临时 X25519 公钥与随机数做 HMAC 认证；服务端验证通过后才分配会话，并在受认证的响应中带回直连候选 (`public_ips`) 与打洞端点。后续所有数据使用 AES-256-GCM。
3. **并行探测与路由选择**：客户端对所有候选 IP 进行并行 UDP 心跳探测测定 RTT 延迟. 优先选择局域网内网 IP (`PathLAN`), 其次按 RTT 选择最优的直连/中继候选。路径分为四类:
   - `PathLAN`: 同局域网直连 (最短路径, 避免房主同一局域网绕行)
   - `PathDirect`: 客户端直连到有公网 IP 的 Left4Proxy 服务器 (真直连, 无需打洞)
   - `PathPunch`: 客户端经打洞/端口映射直连到 NAT 后面的 Left4Proxy 服务器
   - `PathRelay`：客户端经 `server_addrs` 中配置的 UDP 中继入口转发
   候选类型来自可信配置来源：`server_addrs` 作为中继入口，认证握手中的 `public_ips` 作为 Direct/LAN 候选，独立打洞套接字作为 Punch。Ping/Pong 只负责认证候选来源并测量 RTT。
   握手响应还会携带服务端的公网打洞端点 (`stun_server` 反射发现, 或用 `punch_addr` 手动指定)
4. **打洞直连**: 若服务端在 NAT 后且客户端目前只能走代理中继, 客户端会创建打洞套接字:  
   用公网 STUN 服务器反射出该套接字的公网端点, 通过中继把该端点告知服务端  
   服务端据此向客户端打洞 (打开自身 NAT 映射), 双方互发 STUN 探测  
   如果打洞成功且延迟更低, 则会直接直连服务端. 打洞失败或延迟更高将回退中继.
5. **报文代理转发**: 本地 L4D2 客户端（`127.0.0.2:27015`）发出的游戏数据包经认证加密后发送至最优服务端/内网穿透候选节点，服务端验证、解密并转发至实际 L4D2 目标服务器 (`x.x.x.x:27015`)。

数据阶段不会增加额外网络往返；每个数据报只增加 AES-GCM 的 16-byte Tag 与既有协议头。对于约 60–70 KiB/s 的 L4D2 双向流量，这部分带宽和 CPU 开销很小。

## 部署操作

> [!WARNING]
> 这是不兼容的安全协议升级。必须同时更新服务端和全部客户端；旧版 v1 明文报文会被拒绝。旧 YAML 中非空的 `secret:` 字符串也会导致启动报错，请删除该字段并改为部署同目录的 `.secret` 文件。已移除的 `proxy_protocol_v2`、`nat` 与 `direct_port_range` 字段同样需要从旧配置中删除。

1. 部署一个 L4D2 专用服务器. 端口保持 `27015`, ip 开放 `0.0.0.0`.
2. (可选) 部署内网穿透. 远程端口应等于 Left4Proxy 服务端的 `listen_addr` 端口 (默认 `27014`), 而不是 L4D2 的 27015;
   转发目标为 Left4Proxy 服务端，使用 UDP；外部和内部端口尽量保持一致。
3. 部署并首次启动 Left4Proxy Server。它会在服务端 YAML 同目录创建 `.secret`（64 个十六进制字符，代表随机 32-byte 密钥；Unix 权限为 `0600`）。妥善备份该文件。
4. 通过可信渠道把服务端生成的同一个 `.secret` 原样复制到每台客户端 YAML 的同目录。客户端不会自动生成密钥；缺失、格式错误、权限过宽或密钥不匹配都会拒绝连接。不要把它提交到 Git。
5. 在服务端 `public_ips` 内添加可直连到 Left4Proxy 服务端的地址:
   如果你的服务器和内网处于同一局域网. 添加内网 ip `192.168.x.x:27014`
   如果服务端有公网直连地址，也可添加其公网 IP/域名。不要把 frp 等中继入口放进 `public_ips`。
6. 客户端打开 Left4Proxy Client, 在 `server_addrs` 中填写一个或多个内网穿透外部地址. 验证是否可连接
   如果服务器侧还配置了内网 ip 且你和服务器在同一内网, 它应该会自动切换到内网 IP.
7. 启动 Left4Proxy 的服务器和客户端, 求生之路专用服务器和求生之路客户端. 客户端控制台输入 `connect 127.0.0.2` 测试正常连接.

## 救救朋友的答辩网络

> [!IMPORTANT]
> 如果房主(您)自己的网络差是 **没办法** 缓解的.  
> 这种情况下请自费购买服务器或寻找其它网络好的并愿意托管你的服务器的朋友/其他人.
>
> 该说明仅适用于使用内网穿透的服务端.

其实本质上就是多套一层内网穿透节点. 但是"往哪套"是一个问题. 首先判断朋友的网络情况:

#### 加速器/代理软件 (或任何TUN代理流量的软件):  
不支持

- 首先尝试禁用或退出这些软件
- 如果获取的 IP 看起来非 LAN 地址但仍像保留地址 (如 `172` 等) —— 禁用代理软件中的 `fake-ip` 功能.
- 如果获取的公共代理看起来不对 —— 让代理软件绕行 STUN 服务器.

Left4Proxy客户端本体不属于这些类型, 不要关闭它

#### 网络环境本来就差 (Ping哪里都延迟很高), 或遭遇速率限制 (甚至小于 1 MiB/s):  
不支持

请更换您的网络环境. 至少保证游戏时可以分到 128-256 KiB/s 上下行.

#### 移动数据+热点:
看情况.  

移动数据的 NAT 可能比您正在使用的宽带还更严格 (即使用它不一定会帮助您打洞).  
而且还可能遇上 Spike Lag 等情况.
除非启用移动数据后在游戏内实测连接延迟更好时才应该使用.

#### 校园网:
取决于 NAT 受限, 速率限制, 打洞质量等一系列情况.

如果无法打洞(或质量不好)且中继质量也并不好, 可以尝试优化.

#### 共享网络小区/其它NAT受限环境 + 当前内网穿透中继质量不好:

值得尝试

### 创建内网穿透节点并配置

- 优先离你朋友最近的 (同省). 如果没有 尝试离你和朋友都近的节点.
- 优先同运营商(你和朋友都一个运营商) / DNS 三线 / BGP 网络. 如果没有则重新选择节点位置.
- 优先udp外部和内部端口相等 (如果无法分配也可以试试不对等端口 但是未经测试可能有问题)
- 创建 UDP 隧道，并把域名和端口加入各客户端的 `server_addrs`
- 重启 Left4Proxy 服务器 (你) 和 客户端 (朋友)
- 验证 RTT 延迟是否更好 (观察日志有没有自动分流到了这个隧道), 游戏内实测是否更好.
- 如果无明显效果, 则不应该保留该隧道. 

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

服务端配置首次加载时会在同目录创建 `.secret`。该密钥不属于 YAML 字段。

```yaml
listen_addr: ":27014"
target_addr: "127.0.0.1:27015"
# 是否允许自动向本地路由器申请 UPnP 端口映射（默认关闭；会改变路由器状态）
enable_upnp: false
# 填写服务端自身可直连的公网/LAN地址；中继入口填写在客户端 server_addrs
public_ips: []
# 公网 STUN 服务器 (打洞: 让 NAT 后的服务端反射出自己的公网端点)
stun_server: "stun.cloudflare.com:3478"
# 手动指定服务端公网打洞端点 (ip:port); 为空则用 stun_server 自动发现
punch_addr: ""
```

- `listen_addr`: 服务端 UDP 监听地址.
- `target_addr`: 实际 L4D2 服务器监听地址. (避免 Loopback 通常为LAN IP)
- `enable_upnp`: 是否允许服务端自动申请并在退出时释放 UPnP UDP 端口映射。默认关闭；若配置了 `punch_addr`，即使开启也不会触碰 UPnP。
- `public_ips`: 服务端认证后广播给客户端的直连候选列表 (包含服务端自身局域网 IP 与公网域名/IP，不包含 frp 中继)。条目可以写成裸 IP/域名，服务端会自动补实际监听端口；带端口时必须是合法的 `host:port`。
- `stun_server`: 打洞用的公网 STUN 服务器 (默认 `stun.cloudflare.com:3478`, 需可出站访问 UDP 3478). 服务端用它反射出自己的公网端点并广播给客户端.
- `punch_addr`: 手动指定服务端公网打洞端点 (`ip:port`). 有端口映射/固定公网端口时设置可跳过 STUN 反射; 留空则自动发现.

### 客户端配置 (`config.client.yaml`)

启动客户端前，必须把服务端生成的同一个 `.secret` 放到此 YAML 同目录；客户端不会创建或接受字符串密码。

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

- `server_addrs`: 初始中继入口列表，例如一个或多个 frp UDP 隧道的外部地址。
- `listen_addr`: 本地监听地址（默认 `127.0.0.2:27015`，Source 引擎拒绝连接 `127.0.0.1`，故使用其它环回地址）。
- `mode`: 路由模式，支持 `auto`（自动择优）、`direct-only`（只走认证后广播的 Direct/LAN 或 Punch）、`relay-only`（只走 `server_addrs` 中的入口）。指定类型没有可用候选时会停止转发，不会跨类型临时回退。
- `enable_lan`: 是否启用局域网直连检测（同局域网时优先走 LAN，免绕公网）。
- `enable_punch`: 是否启用 STUN 打洞直连（服务端在 NAT 后时，为玩家打洞直连绕过 frp 中继；打洞失败自动回落中继）。
- `ping_interval`: 心跳探测间隔（秒）。
- `stun_server`: 打洞套接字反射公网端点所用的 STUN 服务器（默认 `stun.cloudflare.com:3478`）。

## 构建与运行

### 依赖环境

- Go 1.22 或更高版本

Left4Proxy 的数据面只使用经过认证和加密的 UDP 会话。

### 编译指令

使用项目内置的构建脚本（默认构建 Windows 与 Linux 的 amd64 版本）：

```bash
# 赋予执行权限并构建全部平台
chmod +x build.sh
./build.sh

# 也支持指定子命令构建：
# ./build.sh linux     # 仅构建 Linux (amd64) 版本
# ./build.sh windows   # 仅构建 Windows (amd64) 版本
# ./build.sh server    # 仅构建服务端 (Linux + Windows)
# ./build.sh client    # 仅构建客户端 (Linux + Windows)
# ./build.sh clean     # 清理 bin/ 目录
```

或者使用原生 Go 命令：

```bash
# 编译 Linux 平台版本
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o bin/left4proxy-server-linux-amd64 ./cmd/server
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o bin/left4proxy-client-linux-amd64 ./cmd/client

# 交叉编译 Windows 平台版本
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o bin/left4proxy-server-windows-amd64.exe ./cmd/server
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o bin/left4proxy-client-windows-amd64.exe ./cmd/client
```

### 运行方式

```bash
# 启动服务端
./bin/left4proxy-server -c config.server.yaml

# 启动客户端
./bin/left4proxy-client -c config.client.yaml
```

### 客户端交互命令 (Interactive CLI)

客户端启动后会监听标准输入流，支持在终端输入以下命令查看状态与动态控制：

| 命令 | 别名 | 功能说明 |
| :--- | :--- | :--- |
| `status` | `st`, `s`, `info` | 打印当前连接会话、本地监听、活跃路由模式、本地 NAT 映射类型、游戏连接状态及所有候选节点延迟与 NAT 信息 |
| `ping` | `probe`, `p`, `refresh` | 主动向所有候选节点发送探测包并即时刷新最优路由与 NAT 检测 |
| `nat` | | 主动向多台公网 STUN 服务器发起并发探测，展示详细的 NAT 映射行为与端口增量步长 |
| `mode [模式]` | `m` | 查看当前路由模式或动态切换（支持 `auto`、`direct-only`、`relay-only`） |
| `candidates` | `list`, `ls` | 简要列出当前所有服务端候选节点 |
| `version` | `ver`, `v` | 查看客户端版本号 |
| `help` | `h`, `?` | 显示可用交互命令帮助菜单 |
| `quit` | `exit`, `q` | 优雅停止所有协程并退出客户端 |


## 许可证

本项目遵循 MIT 许可证。
