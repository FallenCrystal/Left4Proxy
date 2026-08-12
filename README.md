# Left4Proxy

> 说明: 本项目及其相关代码与文档由人工智能 (AI) 辅助设计与生成.

Left4Proxy 是一套专为求生之路 2 (Left 4 Dead 2 / Source 引擎) 设计的专用网络代理与动态选路中间件.

系统主要解决内网穿透(如 frp / HAProxy)场景下客户端真实 IP 丢失, 局域网直连优化, STUN UDP 打洞以及 Source 引擎 loopback 地址绑定限制等问题.

> [!IMPORTANT]
>
> 该解决方案是用来解决玩家通过内网穿透时, 所有玩家只能连接到一个 IP 的问题. (匹配, 非 `connect` 命令).  
> 而且部分玩家的网络内网穿透绕一圈可能反而延迟更高的问题.
>
> 其代理特性也注定了它基本上只能用于玩家间私下联机, 因为每位玩家都必须启动客户端才能连接到您的服务器.
> 该软件可能比我们想象的要脆弱 (即不保证它安全/绝对安全), 大规模使用/用于公开游戏可能会使你暴露更多风险.

## 核心特性

- **Source 引擎协议解析与过滤**：校验 `L4DP` 魔法头及 Source 引擎 OOB / NetChannel 数据包结构，隔离非相关网络杂波。
- **Proxy Protocol v2 支持**：服务端支持解析前置代理 (如 frpc / frps / HAProxy) 传入的 PROXY Protocol 报文，提取客户端真实公网 IP 与端口。
- **动态端点发现与选路**: 客户端通过服务端广播的端点列表 (`public_ips`)，自动探测局域网 (LAN)、STUN 直连及服务器中转线路，并根据 RTT 延迟与网络类型完成无缝路由切换。
- **离线探测与自动重连**: 针对 UDP 无连接特性，引入应用层心跳探测机制。服务端离线时客户端静默重试，服务端恢复后自动连接。
- **L4D2 Loopback 绑定适配**: 客户端默认绑定至 `127.0.0.2:27015`，规避 Source 引擎拒绝连接 `127.0.0.1` 本地环回地址的限制.

> 如果您使用内网穿透 (如 frpc) 且支持传递真实IP时, 非常建议启用 Proxy Protocol v2. 因为打洞需要真实 IP.  
> 不传递 IP 的情况下, 流量大概率会经过 LAN (同一局域网) 或 内网穿透中继.

## 架构与工作流程

1. **客户端接入**：客户端启动后连接指定的 Server 地址 (如 frp 穿透域名).
2. **握手与真实 IP 提取**：服务端解析握手请求；若开启 Proxy Protocol，提取真实客户端 IP, 并在响应中带回服务端配置的所有候选 IP 列表 (`public_ips`).
3. **并行探测与路由选择**：客户端对所有候选 IP 进行并行 UDP 心跳探测，测定 RTT 延迟。优先选择局域网内网 IP（`PathLAN`），其次选择打洞直连（`PathDirect`），最后选择中转（`PathRelay`）。
4. **报文代理转发**: 本地 L4D2 客户端（`127.0.0.2:27015`）发出的游戏数据包经 Left4Proxy 封装后发送至最优服务端/内网穿透候选节点，服务端解包并转发至实际 L4D2 目标服务器 (`x.x.x.x:27015`)

## 部署操作

1. 部署一个专用服务器. 端口保持 `27015`, ip开放 `0.0.0.0`.
2. (可选) 部署内网穿透. tcp+udp同端口, 同远程对等. 启用 Proxy Protocol v2 协议.
3. 部署 Left4Proxy Server. `public_ips` 内添加出口IP:  
   如果你的服务器和内网处于同一局域网. 添加内网ip `192.168.x.x:端口`  
   如果你部署了内网穿透. 添加外部内网穿透的ip/域名和端口.  
   警告: 如果开启了 `proxy_protocol_v2`, 不要暴露给未开启此功能的内网穿透. 这可能会导致 IP Spoof.
4. 客户端测打开 Left4Proxy Client, `public_ips` 填内网穿透外部地址. 验证是否可连接  
   如果服务器侧还配置了内网 ip 且你和服务器在同一内网, 它应该会自动切换到内网 IP.
5. 启动 Left4Proxy 的服务器和客户端, 求生之路专用服务器和求生之路客户端. 客户端控制台输入 `connect 127.0.0.2` 测试正常连接.

## 与求生之路的 Matchmaking 配合使用

如果你觉得 `connect` 没什么不便, 且你已经习惯切建图代码了, 切模式也滚瓜烂熟了.  
那这里不是为你准备的.

确保您已经完成了部署操作.

1. 确保求生之路服务器侧配置了 `net_public_adr` 为 `127.0.0.2` 或其它保留地址.
2. 前往控制台输入 `mm_dedicated_force_servers <你刚刚设置的的服务器保留地址>`
   匹配最佳专用服务器前必输入, 否则会匹配不到.
   如果不喜欢每次都输入, 去 `left4dead2/cfg` 目录下 创建/编辑 `autoexec.cfg`. 插入一行
   `bind "F8" "mm_dedicated_force_servers <服务器地址>"`
   可以改键位. 下次匹配前按一下这个键 (F8) 就自己改了
3. 确保求生之路服务器已启动, Left4Proxy 服务器已启动, 所有玩家均正确配置 Left4Client 且开启并连接到了服务器.
4. 与好友一起玩游戏 -> 创建新的大厅 -> 邀请好友 -> 确保 `mm_dedicated_force_servers` 值不为空 -> 选择目前最佳专用 -> 匹配.
5. 应该正常连接. 如果无法匹配:
   - 检查 `net_public_adr` 是否设置有误  
   - Left4Proxy 服务器无法访问本地求生之路服务器. (未正确配置)  
   - 房主(你)的 Left4Proxy 客户端掉了.

## 配置文件说明

### 服务端配置 (`config.server.yaml`)

```yaml
listen_addr: ":27014"
target_addr: "127.0.0.1:27015"
proxy_protocol_v2: true
secret: ""
# 根据实际内网IP和内网穿透IP填
public_ips: []
direct_port_range: "27015"
```

- `listen_addr`: 服务端 UDP 监听地址。
- `target_addr`: 实际 L4D2 服务器监听地址。
- `proxy_protocol_v2`: 是否开启 PROXY Protocol v1/v2 解析（配合 frp/HAProxy 使用）。
- `public_ips`: 服务端广播给客户端的候选节点地址列表（包含局域网 IP 与公网域名/IP）。

### 客户端配置 (`config.client.yaml`)

```yaml
server_addrs: # 支持备选
  - "内网穿透服务器地址:端口号"
listen_addr: "127.0.0.2:27015"
mode: "auto"
enable_lan: true
enable_punch: true
ping_interval: 3
```

- `server_addrs`: 初始连接的服务端地址列表。
- `listen_addr`: 本地监听地址（必须为 `127.0.0.2:27015` 以适配 Source 引擎）。
- `mode`: 路由模式，支持 `auto`（自动择优）、`direct-only`（仅直连）、`relay-only`（仅中转）。
- `ping_interval`: 心跳探测间隔（秒）。

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
