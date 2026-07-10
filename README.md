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
- 设备组、节点、隧道、转发规则、限速、流量采样、审计日志、安装令牌、协议策略。
- 节点端注册、心跳、配置拉取、流量上报、协议违规上报。
- TCP/UDP 转发规则模型，支持基于 revision 的节点同步。
- 协议限制检测，适用于 IEPL/IPLC 等不允许 TLS、QUIC 或加密隧道协议的线路。
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
- `DUSHENG_GOST_PATH` / `DUSHENG_GOST_BIN`：节点端 `gost` 二进制路径，安装脚本会同时写入两者以兼容旧配置。当前第一版入口监听默认由 `dusheng-agent` TCP/UDP runtime 承担，`gost` 保留给后续复杂 tunnel/relay transport。

## 节点 TCP/UDP Runtime

节点端会按面板下发的 TCP / TCP+UDP 转发规则启动本地 TCP listener。连接进入后，agent 会预读首包并执行轻量协议检测，支持 TLS ClientHello SNI/ALPN、HTTP Host、HTTP CONNECT、SOCKS4/5、SSH 和未知明文 TCP。命中协议策略后，`block` 会直接关闭连接并上报违规，`alert` / `observe` 会允许转发并记录事件。

TCP/UDP 转发链路由 agent 直接计量流量，并定时批量上报 `/agent/traffic`。限速、最大连接数和最大 IP 数也在 agent runtime 内执行；UDP v1 按 clientAddr 维护 session，支持 QUIC 首包检测、阻断/告警、计量、限速和空闲清理。`gost` transport adapter 会在后续阶段补齐。

## 节点卸载

在面板「节点」页删除节点时，API 会先把节点标记为 `uninstalling`，并通过下一次 agent 心跳下发 `uninstall` 命令。新版 agent 收到命令后会写入本机卸载标记、回执 API，然后退出；systemd 的 root 权限 `ExecStopPost` 清理器会禁用服务并删除 `/opt/dusheng-agent`、`/etc/dusheng/agent.env`、`/var/lib/dusheng-agent`、`/var/log/dusheng-agent` 等本机文件。API 收到回执后会删除面板里的节点记录。

已安装的旧节点如果没有新版 systemd 清理器，需要重新执行安装命令或升级 agent 后，才能支持面板侧同步卸载。

如果节点离线、卸载失败或长期停留在 `uninstalling`，管理员可以在节点页执行强制删除。强制删除只删除面板记录，不会清理远端机器上的 agent 服务和文件。

## 本地生成 Agent Release 二进制

节点安装脚本默认会从 GitHub Release 下载以下文件：

- `dusheng-agent-linux-amd64.tar.gz`
- `dusheng-agent-linux-arm64.tar.gz`

在当前开发机本地生成 release 资产：

```powershell
cd "D:\DuSheng Panel"
powershell -ExecutionPolicy Bypass -File .\deploy\scripts\build-agent-release.ps1 -Version v0.1.1 -Clean
```

生成文件位于：

```text
release/
```

把以下文件上传到 GitHub Release 后，面板里复制出来的节点安装命令会自动下载对应架构的 agent：

```text
release/dusheng-agent-linux-amd64.tar.gz
release/dusheng-agent-linux-arm64.tar.gz
release/checksums.txt
```

面板生成的节点安装命令会显式带上 `DUSHENG_RELEASE_BASE`，默认指向本仓库最新 Release。若你使用自建下载源，只需在面板端 `.env` 中覆盖 `DUSHENG_AGENT_RELEASE_BASE`。

每次源码提交推送后，也要同步发布 agent 二进制。推荐用本地发布脚本一次完成构建和上传：

```powershell
cd "D:\DuSheng Panel"
powershell -ExecutionPolicy Bypass -File .\deploy\scripts\publish-agent-release.ps1 -Version v0.1.1
```

发布脚本会生成 Linux `amd64` / `arm64` agent 压缩包，创建或更新 GitHub Release，并上传：

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
