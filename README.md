# DuSheng Panel

DuSheng Panel 是一个原创转发面板项目，参考了 flux-panel 和 nyanpass 的产品形态，但不复制它们的代码实现。

项目采用 monorepo 结构，包含 Go 后端 API、Go Linux 节点端 agent，以及 React/Vite 管理面板。

## 定位说明

- 生产部署环境统一按 Linux 设计。
- Windows 只作为当前本地开发环境，不作为生产部署目标。
- 面板端生产部署推荐 Docker Compose。
- 节点端生产部署使用 Linux + systemd。
- 不提供 Windows 服务、Windows 节点端部署脚本或 Windows 生产运行适配。

## 第一版范围

- 管理员/用户登录，认证方式为 JWT。
- 用户、用户线路授权、设备组、节点、逻辑隧道、IEPL 线路资产、A/Z 端点、转发规则、线路探测、限速、流量采样、节点事件、审计日志、安装令牌、协议策略；旧租户数据与 API 保留兼容。
- 节点端注册、能力协商、心跳、配置 ACK/NACK/回滚、TCP/UDP 转发、线路探测、流量上报、协议违规上报。
- TCP/UDP 转发规则模型，支持基于 revision 的节点同步。
- 协议治理检测，适用于 IEPL/IPLC 场景：允许授权 SS/SSH/游戏加速入口，阻断未经授权的代理、VPN、BT、远控和高风险隧道。
- Docker Compose 和 systemd 部署模板。

第一版暂不包含商城、支付、余额、自动续费等商业功能。

## 本地开发

当前开发机是 Windows，因此本地开发命令示例如下：

```powershell
cd "D:\DuSheng Panel"
copy .env.example .env
go run ./apps/api/cmd/api
pnpm install
pnpm dev:web
```

如果 Windows PowerShell 的执行策略阻止 `pnpm` 或 `npm` 运行，请改用 `pnpm.cmd` / `npm.cmd`：

```powershell
pnpm.cmd install
pnpm.cmd dev:web
```

设置 `DUSHENG_LISTEN=127.0.0.1:18888` 后，API 默认监听：

- `http://127.0.0.1:18888`

开发模式下，Vite 面板默认监听：

- `http://127.0.0.1:5173`

Docker Compose 生产部署时，面板默认 HTTP 访问端口为：

- `http://服务器IP:7070`

如需改回 80 或改成其他端口，请在 `.env` 中设置：

```env
HTTP_PORT=7070
HTTPS_PORT=7443
```

默认管理员账号：

- 用户名：`admin_user`
- 密码：`admin_user`

请在非本地开发环境中立即修改默认密码。

## 关键配置

- `DUSHENG_ENV`：本地开发使用 `development`，生产使用 `production`。
- `DUSHENG_JWT_SECRET`：生产环境必须设置为至少 32 个字符，不能使用默认值。
- `DUSHENG_ADMIN_USERNAME` / `DUSHENG_ADMIN_PASSWORD`：生产环境不能同时保留默认管理员账号和密码。
- `DUSHENG_CORS_ORIGINS`：逗号分隔的允许来源；本地可用 `*`，生产必须设置为面板域名或明确的来源 allowlist。
- `DUSHENG_AGENT_RELEASE_BASE`：节点安装脚本下载 agent 二进制的 GitHub Release 地址，默认是 `https://github.com/SatanDS/DuSheng-Panel/releases/latest/download`。
- `DUSHENG_DOWNLOAD_CONNECT_TIMEOUT`：安装器连接下载源的超时秒数，默认 `15`。
- `DUSHENG_DOWNLOAD_MAX_TIME`：单次 Agent 下载的最长秒数，默认 `1800`；设为 `0` 可取消总时长限制。
- `DUSHENG_DOWNLOAD_RETRIES`：Agent 下载失败后的重试次数，默认 `5`；重试会从已下载位置继续。
- `DUSHENG_GOST_PATH` / `DUSHENG_GOST_BIN`：节点端 `gost` 二进制路径，安装脚本会同时写入两者以兼容旧配置。当前第一版入口监听默认由 `dusheng-agent` TCP/UDP runtime 承担，`gost` 保留给后续复杂 tunnel/relay transport。
- `DUSHENG_METRICS_LISTEN`：Agent Prometheus 指标地址，默认仅监听 `127.0.0.1:19090`；设为空可关闭。

## 节点连接地址

- `公网 IP (publicIp)` 由 API 根据 Agent 注册和心跳请求的来源地址自动观测，Agent 不上报、管理员也不手动填写。
- `连接地址 (connectHost)` 由管理员维护，填写用户实际连接节点转发端口时使用的 IP 或域名。普通公网转发可留空；IEPL/IPLC 场景可填写客户端实际可达的专线入口 IP、VIP 或专用域名。
- 对外展示和使用的有效连接地址优先取 `connectHost`；留空时自动回退到 `publicIp`。这里不要填写面板 API 域名，除非该域名本身确实解析到业务转发入口。

## 节点 TCP/UDP Runtime

节点端只在逻辑线路的入口设备组下发业务规则；出口组保留给线路资产、探测和后续 transport adapter，不会重复监听用户端口。Agent 会按 TCP、UDP 或 TCP+UDP 规则启动 listener。TCP 连接进入后会执行有界首包/多包检测，支持 TLS ClientHello SNI/ALPN、HTTP Host、HTTP CONNECT、SOCKS4/5、SSH 和未知明文 TCP。命中协议策略后，`block` 会直接关闭连接并上报违规，`alert` / `observe` 会允许转发并记录事件。

TCP/UDP 转发链路由 agent 直接计量流量，并定时批量上报 `/agent/traffic`。限速、最大连接数和最大 IP 数也在 agent runtime 内执行；UDP v1 按 clientAddr 维护 session，支持 QUIC 首包检测、阻断/告警、计量、限速和空闲清理。`gost` transport adapter 会在后续阶段补齐。

配置应用采用 `warming -> active -> draining` 生命周期。新配置只有在全部 listener 成功预热后才会整体切换；任一端口启动失败会保留上一版并向 API 回报 `rejected` 或 `rolled_back`。同端口策略/上游变更不再立即中断已有连接，旧连接会按单调 generation 在排空超时后收敛。配置租约过期时 Agent 会关闭 listener，避免离线节点永久运行已撤销规则。Agent 会显式上报 capability 列表，API 不再只依赖版本号判断功能支持。

## IEPL 线路资产与探测

「线路资产」独立管理运营商、站点、物理线路、合同带宽、承诺带宽、时延/丢包 SLA、有效期、维护窗口和 A/Z 端点。原有「线路」仍表示逻辑转发隧道，可通过 `lineCircuitId` 绑定实际 IEPL/IPLC 线路。

线路探测由指定 Agent 在节点侧执行，支持 TCP 建连、HTTP 和 UDP 回显。结果写入当前状态与 30 天原始样本，并在 `pending/up/down` 转换时生成节点事件。探测配置带单调 revision，旧 worker 的迟到结果不会覆盖新目标状态。

## 用户授权、配额与租户兼容

默认业务模型是“管理员 -> 用户 -> 转发规则”。管理员创建普通用户后，直接为用户配置线路授权；每条授权可独立限制该线路下的规则数量和入口端口范围。普通用户只会看到直接授权的线路，没有任何授权时不能创建转发规则。缩小授权时 API 会拒绝排除现有监听端口、低于现有规则数或移动仍被规则引用的授权。

已有多租户部署无需迁移数据：带 `TenantID` 且没有直接用户授权的旧账号继续使用租户线路授权；一旦为该普通用户配置任意直接授权，直接授权集合优先生效。租户状态、到期时间和租户配额仍约束保留租户归属的旧账号。租户管理 API 继续提供兼容，但默认面板不再展示租户层级。

用户流量配额、规则总数上限和到期时间直接配置在用户上。旧租户账号的流量上报仍同时计入用户与租户周期，`reportId` 保证重试幂等；任一有效配额耗尽都会停止下发相关规则。规则级协议策略只能由管理员设置，普通用户编辑规则时会保留既有策略，不能覆盖线路或入口组的合规策略。端口由数据库租约按“入口设备组 + Bind IP + transport + port”原子占用，`tcp_udp` 会同时占用 TCP 与 UDP。规则批量导入先预检，再在单个事务内提交，任一规则失败时整批回滚。

## Prometheus 监控

API 在容器内的 `/metrics` 暴露低基数 HTTP、节点、配置回执、规则、用户线路授权、兼容租户状态与配额、物理线路、探测和违规指标；Caddy 默认不对公网转发该路径。Agent 默认在 `127.0.0.1:19090` 暴露 listener 生命周期、连接、配置租约、DPI、流量缓冲和线路探测指标。

启动可选 Prometheus profile：

```bash
docker compose --env-file .env -f deploy/docker-compose.yml --profile monitoring up -d
```

Prometheus 默认仅绑定面板机 `127.0.0.1:19091`，保留 30 天数据。远程 Agent 指标需要通过受控管理网络采集，不建议直接暴露到公网。

## 协议治理与 DPI

协议策略现在按“业务用途”治理，而不是简单禁止所有加密流量。推荐模板包括游戏加速、授权 SS 代理、SSH 运维加速、日常上网、普通转发、严格合规和自定义。PUBG、APEX 这类动态匹配游戏不要求固定服务器 IP/端口，建议使用游戏加速或授权 SS/TUN 入口，再配合连接数、IP 数、速率和流量配额控制。

agent 会先执行轻量首包检测；当策略启用高级/深度/nDPI 检测或配置了阻断协议组时，会调用本机 `dusheng-dpi` sidecar。正式 Release 使用 nDPI 5.0 多包流引擎：Agent 按 TCP 连接或 UDP session 发送带方向和五元组的前 N 个数据块，sidecar 维护有界、可过期的 flow 状态，稳定识别后才执行策略。无 nDPI 的开发构建仍保留启发式 fallback，并在健康检查和节点心跳中明确显示 `heuristic`，不会伪装成 nDPI。sidecar 超时、未稳定或低置信度时，游戏和授权 SS 模板默认降级放行或告警，严格合规模板可配置为告警/阻断。

授权 SS 规则不会尝试解密 SS 2022 内部流量；它按“授权入口”处理，重点绑定用户、端口、源 IP 数、连接数、速率和配额。SSH 运维加速应单独建策略，限制目标服务器和来源，避免和游戏/日常上网规则混用。

## 节点卸载

在面板「节点」页删除节点时，API 会先把节点标记为 `uninstalling`，并通过下一次 agent 心跳下发 `uninstall` 命令。v0.1.5 及以上 agent 收到命令后会写入本机卸载标记、回执 API，然后退出；systemd 的 root 权限 `ExecStopPost` 清理器会禁用服务并删除 `/opt/dusheng-agent`、`/etc/dusheng/agent.env`、`/var/lib/dusheng-agent`、`/var/log/dusheng-agent` 等本机文件。API 收到最终 `done` 回执后会删除面板里的节点记录。

已安装的旧节点如果没有新版 systemd 清理器，需要重新执行安装命令或升级 agent 后，才能支持面板侧同步卸载。

v0.1.4 及更早 agent 只能确认已接收命令，面板会显示 `uninstall_legacy`（旧版卸载待确认）；v0.1.5 及以上 agent 超过 5 分钟没有最终回执会显示 `uninstall_timeout`。这两种状态都不会无限显示卸载中，管理员可以核对远端机器后执行强制删除。强制删除只删除面板记录，不会清理远端机器上的 agent 服务和文件。

## 本地生成 Agent Release 二进制

节点安装脚本默认会从 GitHub Release 下载以下文件；每个压缩包内包含 `dusheng-agent` 和可选 `dusheng-dpi` sidecar：

- `dusheng-agent-linux-amd64.tar.gz`
- `dusheng-agent-linux-arm64.tar.gz`
- `checksums.txt`
- CycloneDX SBOM 与 Sigstore bundle

在当前开发机生成 release 资产。默认使用 Docker Buildx 为 Linux `amd64/arm64` 构建 nDPI sidecar，并在压缩包内携带可替换的 `libndpi.so` 与 LGPLv3 第三方许可说明，节点不需要单独安装 `libndpi`：

```powershell
cd "D:\DuSheng Panel"
powershell -ExecutionPolicy Bypass -File .\deploy\scripts\build-agent-release.ps1 -Version vX.Y.Z -Clean
```

仅用于本地开发或故障回退时，可以显式生成不含真实 nDPI 的启发式版本：

```powershell
powershell -ExecutionPolicy Bypass -File .\deploy\scripts\build-agent-release.ps1 -Version dev -DPIEngine heuristic -Clean
```

生成文件位于：

```text
release/
```

GitHub Actions 会上传以下文件；面板里复制出来的节点安装命令会自动下载对应架构的 agent，并强制核对 `checksums.txt` 中的 SHA256：

```text
release/dusheng-agent-linux-amd64.tar.gz
release/dusheng-agent-linux-arm64.tar.gz
release/checksums.txt
release/*.sbom.cdx.json
release/*.sigstore.json
```

面板生成的节点安装命令会显式带上 `DUSHENG_RELEASE_BASE`，默认指向本仓库最新 Release。若你使用自建下载源，只需在面板端 `.env` 中覆盖 `DUSHENG_AGENT_RELEASE_BASE`。

节点所在地区访问 GitHub 较慢时，可以让面板服务器同步正式 Release，并通过面板域名和 CDN 提供版本化下载。以下命令会先下载到临时目录，核对两个架构压缩包的 SHA256，再原子发布到 `deploy/downloads/v0.1.5`：

```bash
cd /opt/dusheng-panel
./deploy/scripts/sync-agent-release.sh v0.1.5
```

随后在面板服务器的 `.env` 中设置对应的不可变版本地址：

```env
DUSHENG_AGENT_RELEASE_BASE=https://panel.example.com/downloads/v0.1.5
```

Compose 会将 `deploy/downloads` 只读挂载到 Web 容器。自定义宿主机目录时，可同时设置 `DUSHENG_DOWNLOADS_DIR`。修改 `.env` 后需要重新创建 API 和 Web 容器：

```bash
docker compose -f deploy/docker-compose.yml up -d --build --force-recreate api web
curl -fI https://panel.example.com/downloads/v0.1.5/dusheng-agent-linux-amd64.tar.gz
curl -fsS https://panel.example.com/downloads/v0.1.5/checksums.txt
```

版本化 URL 可由 CDN 长期缓存。发布新 Agent 时同步到新的版本目录并更新 `DUSHENG_AGENT_RELEASE_BASE`，不要覆盖已经对外使用的版本目录。

每次源码提交推送后，也要同步发布 agent 二进制。推荐用本地发布脚本一次完成构建和上传：

```powershell
cd "D:\DuSheng Panel"
powershell -ExecutionPolicy Bypass -File .\deploy\scripts\publish-agent-release.ps1 -Version v0.1.1
```

发布脚本会生成 Linux `amd64` / `arm64` agent + DPI sidecar 压缩包，创建或更新 GitHub Release，并上传：

```text
dusheng-agent-linux-amd64.tar.gz
dusheng-agent-linux-arm64.tar.gz
checksums.txt
```

如果没有安装 GitHub CLI 也没关系，脚本会优先读取 `GH_TOKEN` / `GITHUB_TOKEN`，否则尝试使用本机 Git Credential Manager 的 GitHub 凭据。

## 面板部署教程

以下命令在面板服务器上执行。生产环境推荐 Debian 12 或 Ubuntu 22.04+。

### 1. 安装基础依赖

```bash
apt update
apt install -y ca-certificates curl git
curl -fsSL https://get.docker.com | sh
systemctl enable --now docker
```

### 2. 拉取项目

```bash
cd /opt
git clone https://github.com/SatanDS/DuSheng-Panel.git dusheng-panel
cd /opt/dusheng-panel
```

### 3. 创建生产配置

默认面板 HTTP 访问端口是 `7070`。如果你用服务器 IP 访问，推荐这样写：

```bash
cat > .env <<'EOF'
POSTGRES_DB=dusheng
POSTGRES_USER=dusheng
POSTGRES_PASSWORD=请改成数据库强密码

DUSHENG_ENV=production
DUSHENG_JWT_SECRET=请改成至少32位随机长密钥
DUSHENG_ADMIN_USERNAME=admin_user
DUSHENG_ADMIN_PASSWORD=请改成管理员强密码

DUSHENG_PUBLIC_URL=http://你的服务器IP:7070
DUSHENG_CORS_ORIGINS=http://你的服务器IP:7070
DUSHENG_AGENT_RELEASE_BASE=https://github.com/SatanDS/DuSheng-Panel/releases/latest/download

DUSHENG_SITE_ADDRESS=:80
HTTP_PORT=7070
HTTPS_PORT=7443
TZ=Asia/Taipei
EOF
```

注意：`.env` 每一行等号后面不要带行尾空格。数据库密码可以包含 `/`，但仍建议使用字母数字组合，避免 shell、编辑器或复制粘贴引入不可见字符。

如果你使用域名并希望 Caddy 自动申请 HTTPS，建议使用标准 80/443：

```env
DUSHENG_PUBLIC_URL=https://panel.example.com
DUSHENG_CORS_ORIGINS=https://panel.example.com
DUSHENG_SITE_ADDRESS=panel.example.com
HTTP_PORT=80
HTTPS_PORT=443
```

注意：IP + `7070` 部署模式下默认不占用宿主机 `443`，避免和已有 Nginx、宝塔、1Panel、其他 HTTPS 服务冲突。只有域名 HTTPS 部署时才需要把 `HTTPS_PORT` 设为 `443`。

### 4. 启动面板

```bash
docker compose --env-file .env -f deploy/docker-compose.yml up -d --build
```

查看状态：

```bash
docker compose --env-file .env -f deploy/docker-compose.yml ps
docker compose --env-file .env -f deploy/docker-compose.yml logs -f api
```

访问地址：

```text
http://你的服务器IP:7070
```

### 5. 放行端口

如果服务器使用 `ufw`：

```bash
ufw allow 22/tcp
ufw allow 7070/tcp
ufw enable
```

如果使用域名 HTTPS，请放行：

```bash
ufw allow 80/tcp
ufw allow 443/tcp
```

云服务器还需要在安全组中放行对应端口。

### 6. 对接节点端

节点服务器支持 Debian 11、Debian 12、Ubuntu 22.04+，架构支持 `amd64` 和 `arm64`。

在面板中进入节点/安装令牌页面，生成安装令牌并复制安装命令。命令会自动指向 GitHub Release 中的 agent 二进制：

```text
https://github.com/SatanDS/DuSheng-Panel/releases/latest/download
```

在节点服务器执行面板复制出的命令即可。安装完成后检查：

```bash
systemctl status dusheng-agent
journalctl -u dusheng-agent -f
```

### 7. 更新面板

```bash
cd /opt/dusheng-panel
git pull
docker compose --env-file .env -f deploy/docker-compose.yml up -d --build
```

备份、恢复、Release 更新、回滚和安全收尾见 [运维手册](docs/operations.md)。

## 生产部署目标

面板端：

- Linux 服务器
- Docker / Docker Compose
- PostgreSQL 默认生产数据库
- Caddy 或 Nginx 反向代理

节点端：

- Debian 11
- Debian 12
- Ubuntu 22.04+
- 架构：`amd64`、`arm64`
- systemd 服务
- 外部 `gost` 二进制

## 项目结构

- `apps/api`：Go REST API，包含数据库模型、认证、同步接口。
- `apps/agent`：Go 节点端，包含心跳、配置同步、TCP/UDP runtime、协议检测、流量上报和 gost supervisor。
- `apps/web`：React/Vite 管理面板。
- `packages/shared`：OpenAPI 和共享 JSON Schema。
- `deploy`：Docker Compose、反向代理、systemd 和安装脚本。
