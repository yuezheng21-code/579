# 一次性清洗总结（当前可用版本）

> 这份文档用于把到目前为止所有改动、可用点、风险点和上线步骤一次说清，避免重复踩坑。

## 1. 已完成并生效的修复

### 1.1 登录与首页
- 首页可从 `static/` 和项目根目录双路径回退加载 `index.html`（避免 Railway 目录差异导致空白）。
- 登录界面已包含：
  - 可见用户名/密码输入框；
  - 可点击登录按钮；
  - 中/英/德/越/阿/匈语言选项。
- 兼容旧浏览器缓存状态：
  - 自动兼容并迁移 `token/user` 到 `hr_token/hr_user`；
  - 注销会清理新旧 key。

### 1.2 后端鉴权
- 鉴权从“进程内 TOKENS”改为“签名无状态 token（HMAC）”，避免多实例/重启后 token 失效导致登录回跳。
- token 默认 7 天有效期，可用环境变量调整：
  - `HR_TOKEN_SECRET`
  - `HR_TOKEN_TTL`

### 1.3 演示账号（角色测试）
启动时会确保以下账号存在并可登录：
- `admin / admin123`
- `hr / hr123`
- `mgr579 / 579pass`
- `fin / fin123`
- `wh / wh123`
- `worker1 / w123`

### 1.4 安全与功能修复
- 重置密码接口已修复并加权限控制（仅 `admin/hr/mgr`）。
- 密码重置使用项目统一 `hash_password`，不再调用不存在的 bcrypt 逻辑。

### 1.5 Railway 相关
- 已提供 Dockerfile 路径与 Railway 配置，规避 `$PORT` 字符串被 uvicorn 误解析的问题。
- 已提供 SQLite -> PostgreSQL 一次性迁移脚本和中文操作文档。

---

## 2. 当前“能做”和“不能做”

### 能做
1. 正常打开首页并显示登录。
2. 用演示账号登录。
3. 用同一 token 请求受保护接口（如 `/api/analytics/dashboard`）。
4. 将 SQLite 数据迁移到 Railway PostgreSQL（一次性导入）。

### 不能做（本次未做）
1. **应用运行时仍默认 SQLite**。已提供迁移脚本，但业务层还没完全切换为运行时 Postgres。
2. 需要后续把 `database.py` 全量改造为 Postgres/SQLAlchemy 连接层，才是“完全 Postgres 化”。

---

## 3. Railway 部署最小检查清单（上线前 2 分钟）

1. `RAILWAY` 服务变量确认：
   - `PORT`（Railway 自动注入）
   - `HR_TOKEN_SECRET`（建议手工设置一个长随机串）
2. 部署日志中确认启动命令不再出现：
   - `--port '$PORT' is not a valid integer`
3. 浏览器强刷：
   - 开 DevTools -> Application -> Clear storage
   - 勾选 Unregister service workers
4. 登录后立刻检查：
   - `localStorage` 里有 `hr_token`、`hr_user`
   - `GET /api/analytics/dashboard` 返回 200

---

## 4. PostgreSQL 迁移命令（你现在可以直接用）

```bash
python3 migrate_sqlite_to_postgres.py --sqlite-path hr_system.db --truncate
```

迁移后 SQL 校验：

```sql
SELECT COUNT(*) FROM users;
SELECT COUNT(*) FROM employees;
SELECT COUNT(*) FROM timesheet;
```

---

## 5. 若仍“登录后不进系统”，只看这 3 项

1. `/api/login` 是否 200 且返回 `token`；
2. 随后受保护接口是否 200（例如 `/api/analytics/dashboard`）；
3. 浏览器 `localStorage` 是否存在 `hr_token/hr_user`。

> 这三项里哪一项失败，就定位哪一层（前端缓存 / 后端鉴权 / 环境变量）。
