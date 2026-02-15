# 渊博579 HR System (渊博579人力资源管理系统)

派遣管理系统 - 工时、薪资、绩效一体化管理

## 项目简介

这是一个基于 FastAPI 和 SQLite 构建的人力资源管理系统，主要用于派遣员工的工时、薪资和绩效管理。

## 功能特性

- 员工管理
- 考勤管理
- 薪资计算
- 绩效评估
- 仓库工资管理
- 账户管理
- 文件上传

## 技术栈

- **后端**: FastAPI (Python)
- **数据库**: SQLite
- **前端**: HTML/JavaScript (单页应用)
- **部署**: Docker, Railway

## 项目结构

```
.
├── app.py              # FastAPI 主应用
├── database.py         # 数据库操作
├── erp_schema.sql      # 数据库架构
├── requirements.txt    # Python 依赖
├── Dockerfile          # Docker 配置
├── static/             # 静态文件目录
│   └── index.html      # 前端页面
├── uploads/            # 文件上传目录
├── manifest.json       # PWA 配置
├── railway.json        # Railway 部署配置
└── nixpacks.toml       # Nixpacks 配置
```

## 安装和运行

### 本地开发

1. 克隆仓库
```bash
git clone https://github.com/yuezheng21-code/579.git
cd 579
```

2. 安装依赖
```bash
pip install -r requirements.txt
```

3. 运行应用
```bash
uvicorn app:app --host 0.0.0.0 --port 8080
```

4. 访问应用
打开浏览器访问: http://localhost:8080

### Docker 部署

```bash
docker build -t yb579-hr .
docker run -p 8080:8080 yb579-hr
```

### Railway 部署

项目已配置 Railway 部署文件 (`railway.json`)，可以直接连接 GitHub 仓库进行部署。

## 环境变量

- `HR_TOKEN_SECRET`: JWT 令牌密钥（默认: yb579-dev-secret）
- `HR_TOKEN_TTL`: 令牌有效期（秒，默认: 604800，即7天）
- `PORT`: 应用端口（部署平台自动设置）

## 默认账户

系统会自动创建以下演示账户：

- 管理员账户: admin/admin
- 普通用户账户: user/user

## API 文档

启动应用后，访问以下地址查看 API 文档：
- Swagger UI: http://localhost:8080/docs
- ReDoc: http://localhost:8080/redoc

## 开发说明

- 数据库文件 (`*.db`) 已在 `.gitignore` 中排除
- 上传文件存储在 `uploads/` 目录
- 静态文件存储在 `static/` 目录

## License

MIT License

## 作者

yuezheng21-code
