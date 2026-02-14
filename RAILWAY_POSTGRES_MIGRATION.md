# Railway PostgreSQL 迁移指南（从 SQLite）

## 1) 准备

- 你已经在 Railway 开通 PostgreSQL。
- 在服务变量中确认有 `DATABASE_URL`（Railway 自动注入）。
- 本地/容器里有旧的 SQLite 文件：`hr_system.db`。

## 2) 安装依赖

项目已新增迁移依赖 `psycopg2-binary`，确保安装：

```bash
pip install -r requirements.txt
```

## 3) 执行迁移

### 方式 A：使用环境变量（推荐）

```bash
python3 migrate_sqlite_to_postgres.py --sqlite-path hr_system.db --truncate
```

说明：
- `--truncate` 会先清空 PostgreSQL 目标表（适合首迁或覆盖导入）。
- 默认使用 `DATABASE_URL`，默认 schema 是 `public`。

### 方式 B：显式传 PostgreSQL 地址

```bash
python3 migrate_sqlite_to_postgres.py \
  --sqlite-path hr_system.db \
  --postgres-url "$DATABASE_URL" \
  --schema public \
  --truncate
```

## 4) 快速校验

迁移后可在 PostgreSQL 执行：

```sql
SELECT COUNT(*) FROM users;
SELECT COUNT(*) FROM employees;
SELECT COUNT(*) FROM timesheet;
```

若行数与 SQLite 基本一致即迁移成功。

## 5) 部署切换建议（重要）

当前应用主代码仍以 SQLite 驱动运行。要正式切换 PostgreSQL，请继续做这两步：

1. 把 `database.py` 的连接层改为同时支持 PostgreSQL（推荐先引入 SQLAlchemy）。
2. 在 Railway 启动前设置 `DATABASE_URL` 并让应用优先走 Postgres。

> 本次提交先解决“已有 Railway PostgreSQL 怎么把历史数据迁过去”的问题，提供可重复执行的一次性迁移脚本。
