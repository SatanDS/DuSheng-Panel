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

每次 agent 代码变化后，都必须同步发布 Linux agent 二进制，否则节点安装脚本会继续下载旧版本：

```powershell
cd "D:\DuSheng Panel"
powershell -ExecutionPolicy Bypass -File .\deploy\scripts\publish-agent-release.ps1 -Version v0.1.3
```

发布前先确认 GitHub Release 版本号不存在；如果远端已有同名版本，请改用新的版本号，避免覆盖用户正在使用的安装资产。

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

当节点已经离线、卸载失败或长期卡在 `uninstalling` 时，可以在面板中执行强制删除。强制删除只移除面板记录，不会清理远端机器上的 systemd 服务或 `/opt/dusheng-agent` 文件。

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

