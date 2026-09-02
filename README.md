# Left4Proxy

无论你的朋友身处何处, 都不要因网络问题而错失和他们一起玩的机会. 条条大路通罗马, 总有一条适合你.

Left4Proxy 是一套专为求生之路 2 (Left 4 Dead 2 / Source 引擎) 设计的专用网络代理中间件.

只适用于私下联机, 因为每位玩家都必须启动 Left4Proxy 才能连接到您的服务器

该项目的大多数代码都是由 AI 生成的. [查看该项目正在使用的 AI 编码工具和模型](#使用的工具和-ai-模型)  
代码已经经过我和其他数人的测试; 整体代码由独立 Agent 审查, 或在必要时由我介入. 如果有重大功能缺陷或安全问题, 我会尽快处理.  
README 也含有 AI 生成的内容, 但我会自己重写它们.

> [!TIP]
> Left4Proxy **不是** 通用代理软件. 也不是开箱即用软件. (您需要找到适合您自己和兼顾朋友的配置)
> 
> Left4Proxy 客户端只接受一个 UDP 连接并 **只接受已识别的数据包模式** (如 《求生之路》发送的数据包)  
> 暂不确定是否适用于其它起源引擎游戏. 部分数据包 (如 A2S Query) 会经过 Left4Proxy 特殊处理.

## 为什么需要这个?

- 通用组网软件会被杀毒软件杀掉 (通常是虚拟网卡或打洞), 而且普通用户并不会捣鼓这些.
- 默认"本地服务器"打洞: 公用网络/移动热点直接 Symmetric NAT
- 求生之路 IPv4 IP 强绑定: 无法使用 IPv6, 无法充分利用三线DNS分流
- 部分地区部分家宽上行一出省就拉跨

他们的网络不好不是他们的错, 至少 Left4Proxy 可以给你解决这个问题的机会.  
但是如果你服务器的网络本身就拉跨 (没公网IP不算做在内), 那你应该先解决你自己的网络问题, 而不是朋友的网络问题.

而且之后要和你的朋友一起玩, 你也只需要将整个客户端文件夹打包 (即打包 `.secret` 密钥, 配置文件和应用程序本体),  
朋友解压放在某个地方双击运行就能用. 之后联机直接再开就行了

## 特性

具体原理感兴趣自己去翻源代码, 或者让 AI 去翻.

- 端到端加密
- 代理/内网穿透frp支持 (Proxy Protocol)
- 自动打洞 (在内网穿透后面也没关系)
- 自动选择最佳线路, 不可用时无缝切换.
- 自动重连 (但是如果需要这个支撑正常游戏, 那就应该换个网了)
- 服务器广播地址: 添加外部 IP 线路无需调整客户端配置

Left4Proxy 不会因为打了洞就优先选打洞, 而是依旧选择延迟最低的那个.

为了避免求生之路默认的 Loopback 特殊处理导致无法连接. 默认本地 IP 监听实际上会绑定到 `127.0.0.2`

## 部署操作

1. 部署一个 L4D2 专用服务器. 端口保持 `27015`, ip 开放 `0.0.0.0`.
2. (可选) 部署内网穿透.  
   本地端口应使用 Left4Proxy 服务端的 `listen_addr` 端口 (默认 `27014`), 而不是《求生之路》游戏的 27015;  
   转发 `127.0.0.1:27014`, frpc配置侧指定 `proxy_protocol_version = v2`. 在 Left4Proxy 服务端的配置中启用 `proxy_protocol_v2`;  
   如果服务端可以接受非 `127.0.0.1` 的其它代理头, 请将对应的 IP/CIDR 添加到配置的 `proxy_protocol_trusted_addrs` 内
4. 部署并首次启动 Left4Proxy Server. 它会在服务端运行时目录创建 `.secret` 文件. 如果没有该文件, 客户端将无法验证. 
5. 把服务端生成的同一个 `.secret` 放到到每台客户端的运行时目录下. (对于其它要联机的普通玩家, 提前打包好密钥)
6. 在服务端 `public_ips` 内添加声明可以连接到 Left4Proxy 服务端的地址:
   - 如果你的电脑和服务器和内网处于同一局域网. 添加内网 IP `192.168.x.x:27014` 用于直接连接.  
   - 如果服务器有公网直连地址, 直接添加其公网 IP/域名:端口 即可.
   - 这里是地址公告，不是路径分类；即使某地址也经过 frp，最终仍按该连接是否带 PROXY 头分类。
7. 客户端打开 Left4Proxy Client, 在 `server_addrs` 中填写一个或多个可连接到 Left4Proxy 服务端的地址. 验证是否可连接
   如果服务器侧还配置了内网 IP 且你和服务器在同一内网, 它应该会自动切换到内网 IP.
8. 启动 Left4Proxy 的服务器和客户端, 求生之路专用服务器和求生之路客户端. 客户端控制台输入 `connect 127.0.0.2` 测试正常连接.

## 救救朋友的答辩网络

> [!IMPORTANT]
> 如果房主(您)自己的网络差是 **没办法** 缓解的.  
> 这种情况下请自费购买服务器或寻找其它网络好的并愿意托管你的服务器的朋友/其他人.
>
> 该说明仅适用于使用内网穿透的服务端.

其实本质上就是多套一层内网穿透节点. 但是"往哪套"是一个问题. 首先判断朋友的网络情况:

不适用的情况:
- 加速器/代理软件/使用了TUN的代理软件 (首先尝试退出这些软件)
- 网络环境连哪里都很差, 或速率限制无法满足日常上网要求.

值得一试:
- 共享网络/校园网或其它NAT受限环境
- 移动热点 (不要使用 Wifi, 直接用手机线接电脑然后开 USB 网络共享; 放在信号好的地方)

### 创建内网穿透节点并配置

- 优先离你朋友最近的 (同省). 如果没有 尝试离你和朋友都近的节点.
- 优先同运营商(你和朋友都一个运营商) / DNS 三线分流 / BGP 网络. 如果没有则重新选择节点位置.
- 优先udp外部和内部端口相等 (如果无法分配也可以试试不对等端口 但是未经测试可能有问题)
- 创建 UDP 隧道, 并把域名和端口加入各客户端的 `server_addrs`
- 重启 Left4Proxy 服务器 (你) 和 客户端 (朋友)
- 验证 RTT 延迟是否更好 (观察日志有没有自动分流到了这个隧道), 游戏内实测是否更好.
- 如果无明显效果, 则不应该保留该隧道. 

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
5. 确保所有玩家均正确配置 Left4Proxy 客户端且开启并连接到了服务器. (共享配置文件&密钥. 通过压缩包或某种方式分发)
6. 与好友一起玩游戏 -> 创建新的大厅 -> 邀请好友 -> 确保 `mm_dedicated_force_servers` 值不为空 -> 选择目前最佳专用 -> 匹配.
7. 应该正常连接. 如果无法匹配:
   > (不是玩家连不上或掉线! 房主显示"无法匹配到最佳专用服务器 是否使用本地服务器")
   - 检查 `net_public_adr` 是否设置有误  
   - Left4Proxy 服务器无法访问本地求生之路服务器. (未正确配置)  
   - 房主(你)的 Left4Proxy 客户端掉了.

如果一切工作正常, 您和您的朋友都可以加入您的专用服务器. 投票选项将支持 "返回大厅".  
正确配置客户端并连接到您 Left4Proxy 的服务器的玩家也可以在中途加入您的游戏/服务器.

## F&Q

### 玩家因 No Steam Logon 踢出

不是Left4Proxy的锅.

服务器配置 `sv_lan 1` 即可.

不会影响 `mm_dedicated_force_servers` 匹配到您的服务器的行为, 也不会影响 `connect` 命令连接的行为.

### Failed to start client: failed to listen

Failed to start client: failed to listen on local UDP x.x.x.x:27015: bind: An attempt was made to access a socket in a way forbidden by its access permissions.

请先回到主界面或退出游戏 (求生之路). 如果还不行, 尝试关闭防火墙或杀毒软件.

## 配置文件说明

### 服务端配置 (`config.server.yaml`)

服务端配置首次加载时会在同目录创建 `.secret` 文件. 该密钥不属于配置文件字段. 

```yaml
listen_addr: ":27014"
target_addr: "127.0.0.1:27015"
# 仅在 frp/HAProxy UDP 中继的首个数据报附加 PROXY Protocol v1/v2 头时开启
proxy_protocol_v2: false
# 默认只有本机；支持单个 IP 或 CIDR。只限制是否信任 PROXY 头，不限制普通 L4DP 客户端。
proxy_protocol_trusted_addrs:
  - "127.0.0.1"
# 是否允许自动向本地路由器申请 UPnP 端口映射 (默认关闭; 会改变路由器状态) 
enable_upnp: false
# 声明客户端可以尝试连接服务端的地址；实际 Direct/Relay 由 PROXY 头决定
public_ips: []
# 公网 STUN 服务器 (打洞: 让 NAT 后的服务端反射出自己的公网端点)
stun_server: "stun.cloudflare.com:3478"
# 手动指定服务端公网打洞端点 (ip:port); 为空则用 stun_server 自动发现
punch_addr: ""
```

- `listen_addr`: 服务端 UDP 监听地址.
- `target_addr`: 实际 L4D2 服务器监听地址. (避免 Loopback 通常为LAN IP)
- `proxy_protocol_v2`: 是否解析可信 UDP 中继首个数据报附加的 PROXY Protocol v2 头. 每个连接只有首个 UDP 数据报会被解析, 之后所有包都视为普通数据包. 默认为 `false`
- `proxy_protocol_trusted_addrs`: 可提供 PROXY 头的中继来源 IP/CIDR 白名单，默认仅 `127.0.0.1`. 它不要求名单内来源一定携带头，也不会拒绝名单外的普通 L4DP 连接。启用 `proxy_protocol_v2` 时不可显式设为空列表. 名单外来源附加头会记录 `Dropped PROXY header from <ip> because this address is not in proxy_protocol_trusted_addrs`。
- `enable_upnp`: 是否允许服务端自动申请并在退出时释放 UPnP UDP 端口映射. 默认关闭; 若配置了 `punch_addr`, 即使开启也不会触碰 UPnP. 
- `public_ips`: 服务端认证后广播给客户端的可连接地址列表 (可以包含服务端局域网、公网地址或需要尝试的入口). 它只声明地址，不决定 Direct/Relay；实际分类由该候选的认证 Ping/Pong 是否经过 PROXY 头决定。条目可以写成裸 IP/域名, 服务端会自动补实际监听端口; 带端口时必须是合法的 `host:port`.
- `stun_server`: 打洞用的公网 STUN 服务器 (默认 `stun.cloudflare.com:3478`, 需可出站访问 UDP 3478). 服务端用它反射出自己的公网端点并广播给客户端.
- `punch_addr`: 手动指定服务端公网打洞端点 (`ip:port`). 有端口映射/固定公网端口时设置可跳过 STUN 反射; 留空则自动发现.

### 客户端配置 (`config.client.yaml`)

启动客户端前, 必须把服务端生成的同一个 `.secret` 文件放到运行时目录; 客户端不会创建或接受字符串密码. 

```yaml
server_addrs: # 支持备选；每项都是客户端启动时先尝试的服务端地址
  - "可连接到服务端的地址:端口号"
listen_addr: "127.0.0.2:27015"
mode: "auto"
enable_lan: true
enable_punch: true
ping_interval: 3
stun_server: "stun.cloudflare.com:3478"
```

- `server_addrs`: 客户端启动时首先尝试的服务端地址列表，例如 frp UDP 隧道、服务端公网地址或局域网地址。它只声明地址，不决定 Direct/Relay；实际分类由该候选的认证 Ping/Pong 是否经过 PROXY 头决定。
- `listen_addr`: 本地监听地址 (默认 `127.0.0.2:27015`, Source 引擎拒绝连接 `127.0.0.1`, 故使用其它环回地址) . 
- `mode`: 路由模式, 支持 `auto` (自动择优) , `direct-only` (只走认证后标记为 Direct/LAN 或 Punch 的候选) , `relay-only` (只走认证后标记为 Relay 的候选) . 候选来自 `server_addrs` 或 `public_ips` 不影响该判定；指定类型没有可用候选时会停止转发, 不会跨类型临时回退.
- `enable_lan`: 是否启用局域网直连检测 (同局域网时优先走 LAN, 免绕公网) . 
- `enable_punch`: 是否启用 STUN 打洞直连 (服务端在 NAT 后时, 为玩家打洞直连绕过 frp 中继; 打洞失败自动回落中继) . 
- `ping_interval`: 心跳探测间隔 (秒) . 
- `stun_server`: 打洞套接字反射公网端点所用的 STUN 服务器 (默认 `stun.cloudflare.com:3478`) . 

## 构建与运行

### 依赖环境

- Go 1.22 或更高版本

Left4Proxy 的数据面只使用经过认证和加密的 UDP 会话. 

### 编译指令

使用项目内置的构建脚本 (默认构建 Windows 与 Linux 的 amd64 版本) ：

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

客户端启动后会监听标准输入流, 支持在终端输入以下命令查看状态与动态控制：

| 命令 | 别名 | 功能说明 |
| :--- | :--- | :--- |
| `status` | `st`, `s`, `info` | 打印当前连接会话, 本地监听, 活跃路由模式, 本地 NAT 映射类型, 游戏连接状态及所有候选节点延迟与 NAT 信息 |
| `ping` | | 进入每秒刷新的 Braille 点阵延迟/网络质量图表, 显示当前路由, RTT, 探测丢包率, 游戏连接状态. 以及游戏与 L4P 实际上下行速率; 再次输入 `ping` 或 `ping stop` 退出 |
| `probe` | `p`, `refresh` | 主动向所有候选节点发送一次探测包并即时刷新最优路由与 NAT 检测 |
| `nat` | | 主动向多台公网 STUN 服务器发起并发探测, 展示详细的 NAT 映射行为与端口增量步长 |
| `mode [模式]` | `m` | 查看当前路由模式或动态切换 (支持 `auto`, `direct-only`, `relay-only`)  |
| `candidates` | `list`, `ls` | 简要列出当前所有服务端候选节点 |
| `version` | `ver`, `v` | 查看客户端版本号 |
| `help` | `h`, `?` | 显示可用交互命令帮助菜单 |
| `quit` | `exit`, `q` | 优雅停止所有协程并退出客户端 |

## 使用的工具和 AI 模型

- Antigravity
  - Gemini 3.6 Flash (High) : 基础应用程序架构
  - Gemini 3.7 Flash (High) : 打洞优化
- Codex
  - GPT 5.6 Sol (Max) : 测试覆盖, 加密, 代码清理
  - GPT 5.6 Luna (Max) : CLI着色, Ping图标
- Claude Code
  - DeepSeek V4 Flash (High, 0731) : 关键代码审查, STUN 打洞, 错误修复等.  

## 许可证

本项目遵循 MIT 许可证. 
