# DuSheng Panel 运维手册

本文档记录生产环境常用的备份、恢复、更新、回滚和安全收尾步骤。示例默认项目目录为 `/opt/dusheng-panel`，Compose 文件为 `deploy/docker-compose.yml`。

## 更新与 Release

更新面板代码和容器：

```bash
cd /opt/dusheng-panel
git pull
docker compose --env-file .env -f deploy/docker-compose.yml up -d --build
docker compose --env-file .env -f deploy/docker-compose.yml ps
```

每次 agent 或 DPI sidecar 代码变化后，都必须同步发布 Linux agent 二进制包，否则节点安装脚本会继续下载旧版本：

```powershell
cd "D:\DuSheng Panel"
powershell -ExecutionPolicy Bypass -File .\deploy\scripts\publish-agent-release.ps1 -Version v0.1.3
```

发布前先确认 GitHub Release 版本号不存在；如果远端已有同名版本，请改用新的版本号，避免覆盖用户正在使用的安装资产。

Release workflow 会生成 SHA256、CycloneDX SBOM 和 Sigstore bundle。安装脚本默认拒绝无法校验 SHA256 的下载；自建下载源必须同时提供 `checksums.txt`，或显式设置 `DUSHENG_AGENT_SHA256`。`DUSHENG_SKIP_VERIFY=1` 只允许用于可信的临时开发构建。

## 监控

启动 API Prometheus 采集：

```bash
docker compose --env-file .env -f deploy/docker-compose.yml --profile monitoring up -d
curl -fsS http://127.0.0.1:19091/-/healthy
```

API `/metrics` 仅在 Compose 内网直接访问，Caddy 默认不会公开转发。Agent 默认指标地址为 `127.0.0.1:19090`，如需远程采集，应通过 WireGuard、管理 VLAN 或 SSH tunnel，并配置来源访问控制，不能直接监听公网地址。

重点告警建议：节点离线超过 90 秒、`config_status` 为 `rejected/rolled_back/lease_expired`、线路探测连续失败、listener 错误增长、DPI 不可用、traffic buffer 丢弃样本。业务规则只应出现在入口设备组 Agent；出口节点出现业务 listener 应视为配置异常。

## 数据库迁移

API 只使用 `schema_migrations` 中尚未执行的版本化迁移。升级前必须备份 PostgreSQL；迁移成功后不要直接回滚到不认识新 schema 的旧二进制，应优先恢复配套备份或按发布说明执行兼容回滚。

## PostgreSQL 备份

建议更新前、迁移前、批量导入规则前都做一次备份：

```bash
cd /opt/dusheng-panel
mkdir -p backups
docker compose --env-file .env -f deploy/docker-compose.yml exec -T postgres \
  pg_dump -U "${POSTGRES_USER:-dusheng}" "${POSTGRES_DB:-dusheng}" > "backups/dusheng-$(date +%F-%H%M%S).sql"
```

如果 `.env` 中的变量没有被当前 shell 展开，可以直接写实际数据库名和用户名：

```bash
docker compose --env-file .env -f deploy/docker-compose.yml exec -T postgres \
  pg_dump -U dusheng dusheng > backups/dusheng.sql
```

## PostgreSQL 恢复

恢复会覆盖当前库数据，请先停 API，确认备份文件正确，再执行：

```bash
cd /opt/dusheng-panel
docker compose --env-file .env -f deploy/docker-compose.yml stop api web
docker compose --env-file .env -f deploy/docker-compose.yml exec -T postgres \
  psql -U dusheng -d dusheng < backups/dusheng.sql
docker compose --env-file .env -f deploy/docker-compose.yml up -d
```

恢复后检查健康状态和关键列表：

```bash
curl -fsS http://127.0.0.1:7070/healthz
docker compose --env-file .env -f deploy/docker-compose.yml logs --tail=100 api
```

## 回滚

如果新版本启动失败：

```bash
cd /opt/dusheng-panel
git log --oneline -5
git checkout <上一版提交或标签>
docker compose --env-file .env -f deploy/docker-compose.yml up -d --build
```

回滚后不要忘记把 agent release base 指向仍可用的 agent 版本；如果节点已经升级到新 agent，一般可以继续兼容旧 API，但发布前仍建议做一次节点心跳和转发烟测。

## 节点删除与强制删除

普通删除节点会先下发卸载命令，agent 回执后 API 才删除面板记录。适用于节点在线、能正常心跳的情况。

v0.1.4 及更早 agent 接收卸载命令后无法回传最终清理结果，面板会显示“旧版卸载待确认”；v0.1.5 及以上 agent 超过 5 分钟没有最终回执会显示“卸载确认超时”。节点离线、卸载失败或出现上述状态时，可以在核对远端机器后执行强制删除。强制删除只移除面板记录，不会清理远端机器上的 systemd 服务或 `/opt/dusheng-agent` 文件。

## 安全收尾

以下场景需要立即轮换凭据：

- root 密码、SSH 密钥、安装令牌、`.env`、JWT secret 曾经发到聊天、工单、日志或截图里。
- 烟测期间临时开放过安装令牌或管理员密码。
- 发布资产或服务器目录曾经被不可信机器访问。

建议动作：

```bash
passwd
```

然后在面板中撤销不再使用的安装令牌，更新 `.env` 中的 `DUSHENG_JWT_SECRET`、`POSTGRES_PASSWORD`、管理员密码，并重启容器：

```bash
docker compose --env-file .env -f deploy/docker-compose.yml up -d
```
