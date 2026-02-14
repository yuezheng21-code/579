# 一次性清洗与上线总览（Railway）

> 目标：把“登录后仍在登录页 / 部署波动 / 数据迁移”一次性梳理清楚，按本清单执行。

## A. 当前代码关键修复（已在仓库）

1. **登录兼容与防回跳**
   - 前端同时兼容 `hr_token/hr_user` 与历史 `token/user`。
   - 登录成功后双写新旧 key，避免旧缓存用户会话丢失。
2. **前端登录健壮性**
   - API 请求统一捕获网络错误与非 JSON 响应。
   - 登录流程增加完整异常处理，避免按钮卡死、静默失败。
3. **后端鉴权改为无状态签名 token**
   - 不再依赖进程内存 token 表，减少多实例/重启导致的 401。
4. **演示账号兜底**
   - 启动时确保 `admin/hr/mgr/fin/wh/worker` 账号可用，便于验收。
5. **SQLite -> PostgreSQL 迁移工具**
   - `migrate_sqlite_to_postgres.py` 可一次性迁移历史数据到 Railway PG。

## B. Railway 一次性清洗步骤（推荐原样执行）

1. 在 Railway **Variables** 中确认：
   - `PORT`（平台注入）
   - `DATABASE_URL`（PostgreSQL 服务注入）
2. 触发 **Redeploy**，并选择 **Clear build cache / 清缓存部署**。
3. 浏览器端做一次强清理：
   - DevTools -> Application -> Storage -> **Clear site data**。
4. 重新打开域名，登录测试以下账号：
   - `admin/admin123`
   - `hr/hr123`
   - `mgr579/579pass`

## C. 数据迁移到 PostgreSQL

```bash
python3 migrate_sqlite_to_postgres.py --sqlite-path hr_system.db --truncate
```

迁移后校验：

```sql
SELECT COUNT(*) FROM users;
SELECT COUNT(*) FROM employees;
SELECT COUNT(*) FROM timesheet;
```

## D. 验收口径（通过标准）

1. 登录后立即进入系统首页（不回登录页）。
2. 刷新页面后仍保持登录态。
3. 退出登录后能回到登录页，并可重新登录。
4. 三个角色菜单权限表现不同（admin/hr/mgr）。

## E. 仍异常时的最小定位

1. 看 `POST /api/login` 响应是否有 `token`。
2. 看 `GET /api/analytics/dashboard` 是否 `200`，且请求头带 `Authorization: Bearer ...`。
3. 若 `401`：说明 token 无效或后端实例配置不一致。
4. 若 `404 Not Found` 首页：说明路由/静态文件路径仍有偏差，优先检查 Railway 构建入口和镜像版本。
