"""渊博+579 HR V6 — FastAPI Backend (Enhanced with Account Management & Warehouse Salary)"""
import os, json, uuid, shutil, secrets, string, traceback, threading, logging, sys, copy
from datetime import datetime
from fastapi import FastAPI, HTTPException, Depends, UploadFile, File, Form, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
import database
import re

app = FastAPI(title="渊博579 HR V6")
# CORS: Restrict to specific origins in production. Use "*" only for development.
ALLOWED_ORIGINS = os.environ.get("ALLOWED_ORIGINS", "*").split(",")
app.add_middleware(
    CORSMiddleware, 
    allow_origins=ALLOWED_ORIGINS, 
    allow_credentials=True, 
    allow_methods=["*"], 
    allow_headers=["*"]
)

UPLOAD_DIR = os.path.join(os.path.dirname(__file__), "uploads")
STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(STATIC_DIR, exist_ok=True)

_db_ready = False

@app.on_event("startup")
def on_startup():
    def _init_database():
        global _db_ready
        try:
            database.init_db()
            database.seed_data()
            database.ensure_demo_users()
            _db_ready = True
            print("✅ Database initialized successfully")
        except Exception as e:
            print(f"⚠️ Database initialization error: {e}")
            traceback.print_exc()

    threading.Thread(target=_init_database, daemon=True).start()

@app.on_event("shutdown")
def on_shutdown():
    logging.getLogger("uvicorn.error").info("Application shutting down gracefully")

import hashlib, time, hmac, base64

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(password, hashed):
    return hash_password(password) == hashed

SECRET_KEY = os.environ.get("HR_TOKEN_SECRET")
if not SECRET_KEY:
    # In production, this should raise an error. For development, use a dev key.
    if os.environ.get("ENV") == "production":
        raise ValueError("HR_TOKEN_SECRET environment variable must be set in production")
    SECRET_KEY = "yb579-dev-secret"
TOKEN_TTL_SECONDS = int(os.environ.get("HR_TOKEN_TTL", 60 * 60 * 24 * 7))

def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")

def _b64url_decode(data: str) -> bytes:
    padding = "=" * ((4 - len(data) % 4) % 4)
    return base64.urlsafe_b64decode(data + padding)

def make_token(username, role, extra: Optional[dict] = None):
    payload = {"u": username, "r": role, "iat": int(time.time())}
    if extra:
        payload.update(extra)
    body = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    sig = hmac.new(SECRET_KEY.encode(), body.encode(), hashlib.sha256).hexdigest()
    return f"{body}.{sig}"

def _parse_token(token: str):
    try:
        body, sig = token.split(".", 1)
    except ValueError:
        raise HTTPException(401, "Unauthorized")
    expected = hmac.new(SECRET_KEY.encode(), body.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected):
        raise HTTPException(401, "Unauthorized")
    try:
        payload = json.loads(_b64url_decode(body).decode())
    except Exception:
        raise HTTPException(401, "Unauthorized")
    if int(time.time()) - int(payload.get("iat", 0)) > TOKEN_TTL_SECONDS:
        raise HTTPException(401, "Token expired")
    return payload

def generate_password(length=8):
    """生成随机密码"""
    chars = string.ascii_letters + string.digits
    return ''.join(secrets.choice(chars) for _ in range(length))

def get_current_year():
    """获取当前年份"""
    return datetime.now().year

def get_current_year_month():
    """获取当前年月，格式: YYYY-MM"""
    return datetime.now().strftime("%Y-%m")

def get_user(request: Request):
    token = request.headers.get("Authorization","").replace("Bearer ","")
    if not token:
        raise HTTPException(401, "Unauthorized")
    payload = _parse_token(token)
    username = payload.get("u")
    if not username:
        raise HTTPException(401, "Unauthorized")
    db = database.get_db()
    try:
        u = db.execute("SELECT * FROM users WHERE username=? AND active=1", (username,)).fetchone()
        if u:
            return dict(u)
        if payload.get("pin"):
            emp = db.execute("SELECT id,name,primary_wh FROM employees WHERE id=?", (username,)).fetchone()
            if emp:
                return {"username": emp["id"], "display_name": emp["name"], "role": "worker", "employee_id": emp["id"], "warehouse_code": emp["primary_wh"]}
        raise HTTPException(401, "Unauthorized")
    finally:
        db.close()

# Whitelist of allowed table names to prevent SQL injection
ALLOWED_TABLES = {
    "employees", "users", "timesheet", "leave_requests", "expense_claims",
    "performance_reviews", "warehouses", "suppliers", "business_lines",
    "employee_grades", "warehouse_salary_config", "leave_balances",
    "dispatch_needs", "container_tasks", "audit_logs", "container_records",
    "grade_levels", "grade_evaluations", "promotion_applications",
    "bonus_applications", "quotation_templates", "quotation_records",
    "employee_files", "leave_types", "talent_pool", "recruit_progress",
    "schedules", "messages", "permission_overrides"
}

# Table-specific allowed order columns for validation
TABLE_ORDER_COLUMNS = {
    "employees": ["id", "created_at", "updated_at", "name", "grade", "status"],
    "users": ["created_at", "username", "id"],
    "timesheet": ["id", "created_at", "updated_at", "work_date", "employee_id"],
    "leave_requests": ["id", "created_at", "start_date", "end_date"],
    "expense_claims": ["id", "created_at", "status"],
    "performance_reviews": ["id", "created_at"],
    "warehouses": ["code", "name"],
    "suppliers": ["id", "name"],
    "business_lines": ["id", "name"],
    "employee_grades": ["id", "grade"],
    "warehouse_salary_config": ["id", "created_at", "updated_at", "warehouse_code", "grade", "position_type"],
    "leave_balances": ["id", "employee_id"],
    "dispatch_needs": ["id", "created_at"],
    "container_tasks": ["id", "created_at"],
    "audit_logs": ["id", "timestamp"],
    "container_records": ["id", "created_at"],
    "grade_levels": ["id", "series", "level"],
    "grade_evaluations": ["id", "created_at"],
    "promotion_applications": ["id", "created_at"],
    "bonus_applications": ["id", "created_at"],
    "quotation_templates": ["id", "created_at"],
    "quotation_records": ["id", "created_at"],
    "employee_files": ["id", "created_at", "employee_id"],
    "leave_types": ["id", "code"],
    "talent_pool": ["id", "created_at"],
    "recruit_progress": ["id", "created_at"],
    "schedules": ["id", "created_at", "work_date"],
    "messages": ["id", "created_at", "timestamp"],
    "permission_overrides": ["id", "role", "module"],
}

def _validate_table_name(table: str):
    """Validate table name to prevent SQL injection"""
    if table not in ALLOWED_TABLES:
        raise HTTPException(400, f"Invalid table name: {table}")
    return table

def _validate_order_clause(order: str, table: str):
    """Validate ORDER BY clause to prevent SQL injection"""
    # Allow multiple columns separated by commas, each with optional DESC/ASC
    # Split by comma and validate each part
    parts = [part.strip() for part in order.split(',')]
    
    for part in parts:
        # Allow simple column names with optional DESC/ASC
        pattern = r'^(\w+)(\s+(DESC|ASC))?$'
        match = re.match(pattern, part, re.IGNORECASE)
        if not match:
            raise HTTPException(400, f"Invalid order clause part: {part}")
        
        column = match.group(1)
        # Check if column is allowed for this specific table
        allowed_cols = TABLE_ORDER_COLUMNS.get(table, ["id"])
        if column not in allowed_cols:
            raise HTTPException(400, f"Invalid order column '{column}' for table '{table}'")
    
    return order

def q(table, where="1=1", params=(), order="id DESC", limit=500):
    _validate_table_name(table)
    _validate_order_clause(order, table)
    
    # Ensure limit is an integer
    try:
        limit = int(limit)
        if limit <= 0 or limit > 1000:
            limit = 500
    except (ValueError, TypeError):
        limit = 500
    
    db = database.get_db()
    try:
        rows = db.execute(f"SELECT * FROM {table} WHERE {where} ORDER BY {order} LIMIT {limit}", params).fetchall()
        return [dict(r) for r in rows]
    finally:
        db.close()

def insert(table, data: dict):
    _validate_table_name(table)
    db = database.get_db()
    try:
        cols = ",".join(data.keys())
        phs = ",".join(["?"]*len(data))
        db.execute(f"INSERT INTO {table}({cols}) VALUES({phs})", list(data.values()))
        db.commit()
    finally:
        db.close()

def update(table, id_col, id_val, data: dict):
    _validate_table_name(table)
    db = database.get_db()
    try:
        sets = ",".join(f"{k}=?" for k in data.keys())
        db.execute(f"UPDATE {table} SET {sets} WHERE {id_col}=?", list(data.values())+[id_val])
        db.commit()
    finally:
        db.close()

def audit_log(username: str, action: str, resource_type: str, resource_id: str, details: str = ""):
    """记录审计日志"""
    try:
        db = database.get_db()
        # Use the actual schema of audit_logs table
        db.execute("""
            INSERT INTO audit_logs (username, action, target_table, target_id, new_value)
            VALUES (?, ?, ?, ?, ?)
        """, (username, action, resource_type, resource_id, details))
        db.commit()
        db.close()
    except Exception as e:
        # Log the failure but don't fail the operation
        import sys
        print(f"AUDIT LOG FAILURE: {username} {action} {resource_type}/{resource_id} - Error: {e}", file=sys.stderr)

# ── Auth ──
class LoginReq(BaseModel):
    username: str
    password: str

class PinReq(BaseModel):
    pin: str

class AccountGenerateReq(BaseModel):
    employee_id: str
    role: str = "worker"

class BatchAccountGenerateReq(BaseModel):
    employee_ids: list[str]
    role: str = "worker"

class PasswordResetReq(BaseModel):
    username: str

class TimesheetCreateReq(BaseModel):
    employee_id: str
    work_date: str
    warehouse_code: str
    hours: float = 0
    grade: Optional[str] = None
    position: Optional[str] = "库内"

@app.get("/health")
def health_check():
    """Health check endpoint for Railway monitoring"""
    return {"status": "ok", "db_ready": _db_ready}

@app.post("/api/login")
def login(req: LoginReq):
    db = database.get_db()
    u = db.execute("SELECT * FROM users WHERE username=? AND active=1", (req.username,)).fetchone()
    db.close()
    if not u or not verify_password(req.password, u["password_hash"]):
        raise HTTPException(401, "用户名或密码错误")
    token = make_token(u["username"], u["role"])
    return {"token": token, "user": {"username": u["username"], "display_name": u["display_name"], "role": u["role"], "employee_id": u["employee_id"]}}

@app.post("/api/pin-login")
def pin_login(req: PinReq):
    db = database.get_db()
    emp = db.execute("SELECT * FROM employees WHERE pin=?", (req.pin,)).fetchone()
    db.close()
    if not emp: raise HTTPException(401, "PIN无效")
    token = make_token(emp["id"], "worker", {"pin": 1})
    return {"token": token, "user": {"username": emp["id"], "display_name": emp["name"], "role": "worker", "employee_id": emp["id"]}}

# ── Employees ──
@app.get("/api/employees")
def get_employees(user=Depends(get_user)): return q("employees")

@app.get("/api/employees/{eid}")
def get_employee(eid: str, user=Depends(get_user)):
    emps = q("employees", "id=?", (eid,))
    if not emps: raise HTTPException(404, "员工不存在")
    return emps[0]

@app.post("/api/employees")
async def create_employee(request: Request, user=Depends(get_user)):
    data = await request.json()
    if "id" not in data: data["id"] = f"YB-{uuid.uuid4().hex[:6].upper()}"
    insert("employees", data); return {"ok": True, "id": data["id"]}

@app.put("/api/employees/{eid}")
async def update_employee(eid: str, request: Request, user=Depends(get_user)):
    data = await request.json(); data["updated_at"] = datetime.now().isoformat()
    update("employees", "id", eid, data); return {"ok": True}

# ── Account Management ──
@app.get("/api/accounts")
def get_accounts(user=Depends(get_user)):
    """获取所有员工账号状态"""
    db = database.get_db()
    rows = db.execute("""
        SELECT e.id, e.name, e.grade, e.primary_wh, e.status, e.has_account,
               u.username, u.role, u.active as account_active
        FROM employees e
        LEFT JOIN users u ON u.employee_id = e.id
        WHERE e.status = '在职'
        ORDER BY e.id
    """).fetchall()
    db.close()
    return [dict(r) for r in rows]

@app.post("/api/accounts/generate")
async def generate_account(request: Request, user=Depends(get_user)):
    """为员工生成账号"""
    data = await request.json()
    employee_id = data.get("employee_id")
    role = data.get("role", "worker")

    db = database.get_db()
    emp = db.execute("SELECT * FROM employees WHERE id=?", (employee_id,)).fetchone()
    if not emp:
        db.close()
        raise HTTPException(404, "员工不存在")

    # 检查是否已有账号
    existing = db.execute("SELECT * FROM users WHERE employee_id=?", (employee_id,)).fetchone()
    if existing:
        db.close()
        raise HTTPException(400, "该员工已有账号")

    # 生成用户名和密码
    username = employee_id.lower().replace("-", "")
    password = generate_password(8)
    password_hash = hash_password(password)

    # 创建账号
    db.execute("""INSERT INTO users(username, password_hash, display_name, role, employee_id, warehouse_code, biz_line)
                  VALUES(?,?,?,?,?,?,?)""",
               (username, password_hash, emp["name"], role, employee_id, emp["primary_wh"], emp["biz_line"]))

    # 更新员工表
    db.execute("UPDATE employees SET has_account=1 WHERE id=?", (employee_id,))
    db.commit()
    db.close()

    return {"ok": True, "username": username, "password": password, "display_name": emp["name"]}

@app.post("/api/accounts/batch-generate")
async def batch_generate_accounts(request: Request, user=Depends(get_user)):
    """批量生成账号"""
    data = await request.json()
    employee_ids = data.get("employee_ids", [])
    role = data.get("role", "worker")

    results = []
    db = database.get_db()
    
    try:
        for eid in employee_ids:
            emp = db.execute("SELECT * FROM employees WHERE id=?", (eid,)).fetchone()
            if not emp: continue

            existing = db.execute("SELECT * FROM users WHERE employee_id=?", (eid,)).fetchone()
            if existing: continue

            username = eid.lower().replace("-", "")
            password = generate_password(8)
            password_hash = hash_password(password)

            db.execute("""INSERT INTO users(username, password_hash, display_name, role, employee_id, warehouse_code, biz_line)
                          VALUES(?,?,?,?,?,?,?)""",
                       (username, password_hash, emp["name"], role, eid, emp["primary_wh"], emp["biz_line"]))
            db.execute("UPDATE employees SET has_account=1 WHERE id=?", (eid,))

            results.append({"employee_id": eid, "username": username, "password": password, "name": emp["name"]})

        db.commit()
        return {"ok": True, "accounts": results}
    except Exception as e:
        db.rollback()
        raise HTTPException(500, f"批量生成账号失败: {str(e)}")
    finally:
        db.close()

@app.post("/api/accounts/reset-password")
async def reset_password(request: Request, user=Depends(get_user)):
    """重置密码"""
    if user.get("role") not in ["admin", "hr", "mgr"]:
        raise HTTPException(403, "无权限执行密码重置")

    data = await request.json()
    username = data.get("username")

    db = database.get_db()
    u = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    if not u:
        db.close()
        raise HTTPException(404, "账号不存在")

    new_password = generate_password(8)
    password_hash = hash_password(new_password)
    db.execute("UPDATE users SET password_hash=? WHERE username=?", (password_hash, username))
    db.commit()
    db.close()

    # Audit log
    audit_log(user.get("username", ""), "reset_password", "user", username, 
              f"密码由 {user.get('username')} 重置")

    return {"ok": True, "username": username, "password": new_password}

@app.put("/api/accounts/{username}/toggle")
async def toggle_account(username: str, user=Depends(get_user)):
    """启用/禁用账号"""
    db = database.get_db()
    u = db.execute("SELECT active FROM users WHERE username=?", (username,)).fetchone()
    if not u:
        db.close()
        raise HTTPException(404, "账号不存在")

    new_status = 0 if u["active"] else 1
    db.execute("UPDATE users SET active=? WHERE username=?", (new_status, username))
    db.commit()
    db.close()
    
    # Audit log
    action = "enable_account" if new_status else "disable_account"
    audit_log(user.get("username", ""), action, "user", username,
              f"账号{'启用' if new_status else '禁用'}由 {user.get('username')} 执行")
    
    return {"ok": True, "active": new_status}

# ── My Page (员工个人页面) ──
@app.get("/api/mypage")
def get_mypage(user=Depends(get_user)):
    """获取当前登录员工的个人信息"""
    employee_id = user.get("employee_id")
    if not employee_id:
        raise HTTPException(400, "当前用户未关联员工信息")

    db = database.get_db()
    emp = db.execute("SELECT * FROM employees WHERE id=?", (employee_id,)).fetchone()
    if not emp:
        db.close()
        raise HTTPException(404, "员工信息不存在")

    current_year = get_current_year()
    current_year_month = get_current_year_month()

    # 获取工时统计
    ts_stats = db.execute("""
        SELECT warehouse_code, COUNT(*) as days, SUM(hours) as total_hours,
               SUM(hourly_pay) as total_pay, SUM(net_pay) as total_net
        FROM timesheet
        WHERE employee_id=? AND work_date LIKE ?
        GROUP BY warehouse_code
    """, (employee_id, f"{current_year}-%")).fetchall()

    # 获取本月工时
    monthly_stats = db.execute("""
        SELECT SUM(hours) as hours, SUM(hourly_pay) as pay, SUM(net_pay) as net
        FROM timesheet
        WHERE employee_id=? AND work_date LIKE ?
    """, (employee_id, f"{current_year_month}%")).fetchone()

    # 获取假期余额
    leave_balances = db.execute("""
        SELECT leave_type, total_days, used_days, remaining_days
        FROM leave_balances
        WHERE employee_id=? AND year=?
    """, (employee_id, current_year)).fetchall()

    # 获取最近工时记录
    recent_ts = db.execute("""
        SELECT work_date, warehouse_code, start_time, end_time, hours,
               hourly_pay, net_pay, wh_status
        FROM timesheet
        WHERE employee_id=?
        ORDER BY work_date DESC
        LIMIT 20
    """, (employee_id,)).fetchall()

    db.close()

    return {
        "employee": dict(emp),
        "warehouse_stats": [dict(r) for r in ts_stats],
        "monthly_stats": dict(monthly_stats) if monthly_stats else {"hours": 0, "pay": 0, "net": 0},
        "leave_balances": [dict(r) for r in leave_balances],
        "recent_timesheet": [dict(r) for r in recent_ts]
    }

@app.get("/api/mypage/salary-config")
def get_my_salary_config(user=Depends(get_user)):
    """获取当前员工在各仓库的薪资配置"""
    employee_id = user.get("employee_id")
    if not employee_id:
        raise HTTPException(400, "当前用户未关联员工信息")

    db = database.get_db()
    emp = db.execute("SELECT grade, position, primary_wh, dispatch_whs FROM employees WHERE id=?", (employee_id,)).fetchone()
    if not emp:
        db.close()
        raise HTTPException(404, "员工信息不存在")

    # 获取员工可能工作的仓库列表
    wh_list = [emp["primary_wh"]] if emp.get("primary_wh") else []
    if emp.get("dispatch_whs"):
        dispatch_list = [wh.strip() for wh in emp["dispatch_whs"].split(",") if wh.strip()]
        wh_list.extend(dispatch_list)
    wh_list = list(set(filter(None, wh_list)))

    # 获取各仓库的薪资配置
    configs = []
    for wh in wh_list:
        cfg = db.execute("""
            SELECT wsc.*, w.name as warehouse_name
            FROM warehouse_salary_config wsc
            JOIN warehouses w ON w.code = wsc.warehouse_code
            WHERE wsc.warehouse_code=? AND wsc.grade=?
        """, (wh, emp["grade"])).fetchall()
        for c in cfg:
            configs.append(dict(c))

    db.close()
    return {"configs": configs}

# ── Warehouse Salary Config ──
@app.get("/api/warehouse-salary-config")
def get_wh_salary_config(warehouse_code: Optional[str] = None, user=Depends(get_user)):
    """获取仓库薪资配置"""
    if warehouse_code:
        return q("warehouse_salary_config", "warehouse_code=?", (warehouse_code,), order="grade ASC, position_type ASC")
    return q("warehouse_salary_config", order="warehouse_code ASC, grade ASC, position_type ASC")

@app.post("/api/warehouse-salary-config")
async def create_wh_salary_config(request: Request, user=Depends(get_user)):
    """创建仓库薪资配置"""
    data = await request.json()
    data["id"] = f"WSC-{data['warehouse_code']}-{data['grade']}-{data.get('position_type','库内')}"
    data["created_at"] = datetime.now().isoformat()
    data["updated_at"] = datetime.now().isoformat()
    insert("warehouse_salary_config", data)
    return {"ok": True, "id": data["id"]}

@app.put("/api/warehouse-salary-config/{config_id}")
async def update_wh_salary_config(config_id: str, request: Request, user=Depends(get_user)):
    """更新仓库薪资配置"""
    data = await request.json()
    data["updated_at"] = datetime.now().isoformat()
    update("warehouse_salary_config", "id", config_id, data)
    return {"ok": True}

@app.get("/api/salary-rate")
def get_salary_rate(warehouse_code: str, grade: str, position_type: str = "库内", user=Depends(get_user)):
    """获取特定仓库+职级+岗位的薪资标准"""
    db = database.get_db()
    cfg = db.execute("""
        SELECT * FROM warehouse_salary_config
        WHERE warehouse_code=? AND grade=? AND position_type=?
    """, (warehouse_code, grade, position_type)).fetchone()

    if not cfg:
        # 如果没有特定配置，返回职级默认值
        grade_info = db.execute("SELECT base_salary FROM grade_levels WHERE code=?", (grade,)).fetchone()
        db.close()
        if grade_info:
            return {"hourly_rate": grade_info["base_salary"], "source": "grade_default"}
        return {"hourly_rate": 11.0, "source": "system_default"}

    db.close()
    return dict(cfg)

# ── Suppliers ──
@app.get("/api/suppliers")
def get_suppliers(user=Depends(get_user)): return q("suppliers")

@app.post("/api/suppliers")
async def create_supplier(request: Request, user=Depends(get_user)):
    data = await request.json()
    if "id" not in data: data["id"] = f"SUP-{uuid.uuid4().hex[:4].upper()}"
    insert("suppliers", data); return {"ok": True, "id": data["id"]}

# ── Warehouses ──
@app.get("/api/warehouses")
def get_warehouses(user=Depends(get_user)): return q("warehouses", order="code ASC")

# ── Timesheet ──
@app.get("/api/timesheet")
def get_timesheet(employee_id: Optional[str] = None, user=Depends(get_user)):
    if employee_id:
        return q("timesheet", "employee_id=?", (employee_id,), order="work_date DESC, employee_id ASC")
    return q("timesheet", order="work_date DESC, employee_id ASC")

@app.post("/api/timesheet")
async def create_timesheet(request: Request, user=Depends(get_user)):
    data = await request.json()
    if "id" not in data: data["id"] = f"WT-{uuid.uuid4().hex[:8]}"

    # 检查是否已存在相同的工时记录
    employee_id = data.get("employee_id")
    work_date = data.get("work_date")
    warehouse_code = data.get("warehouse_code")
    
    if employee_id and work_date and warehouse_code:
        db = database.get_db()
        existing = db.execute("""
            SELECT id FROM timesheet 
            WHERE employee_id=? AND work_date=? AND warehouse_code=?
        """, (employee_id, work_date, warehouse_code)).fetchone()
        
        if existing:
            db.close()
            raise HTTPException(400, f"该员工在该日期和仓库已有工时记录 (ID: {existing['id']})")
        
        db.close()

    # 根据仓库获取薪资配置
    wh = data.get("warehouse_code")
    grade = data.get("grade")
    position = data.get("position", "库内")

    if wh and grade:
        db = database.get_db()
        cfg = db.execute("""
            SELECT * FROM warehouse_salary_config
            WHERE warehouse_code=? AND grade=? AND position_type=?
        """, (wh, grade, position)).fetchone()

        if cfg:
            data["base_rate"] = cfg["hourly_rate"]
            # 计算应付工资
            hours = float(data.get("hours", 0))
            data["hourly_pay"] = round(cfg["hourly_rate"] * hours, 2)
        db.close()

    insert("timesheet", data)
    return {"ok": True}

# ── Payroll Summary ──
@app.get("/api/payroll-summary")
def get_payroll_summary(month: Optional[str] = None, user=Depends(get_user)):
    """
    获取指定月份（YYYY-MM）的工资汇总。未指定 month 时默认为当前月。
    返回每个员工在该月的工时、毛工资(net_pay)汇总。
    """
    # Determine target month
    if not month:
        month = datetime.now().strftime("%Y-%m")

    db = database.get_db()
    rows = db.execute(
        """
        SELECT t.employee_id, e.name, e.grade,
               SUM(t.hours) AS total_hours,
               SUM(t.hourly_pay) AS total_gross,
               SUM(t.net_pay) AS total_net
        FROM timesheet t
        JOIN employees e ON t.employee_id = e.id
        WHERE t.work_date LIKE ? || '%'
        GROUP BY t.employee_id
        ORDER BY e.grade ASC, e.name ASC
        """,
        (month,)
    ).fetchall()
    db.close()
    return [dict(r) for r in rows]

@app.post("/api/timesheet/batch-approve")
async def batch_approve(request: Request, user=Depends(get_user)):
    body = await request.json()
    db = database.get_db()
    try:
        for tid in body.get("ids", []):
            if body.get("type") == "wh":
                db.execute("UPDATE timesheet SET wh_status='已仓库审批',wh_approver=?,wh_approve_time=? WHERE id=?",
                           (user.get("display_name",""), datetime.now().isoformat(), tid))
            else:
                db.execute("UPDATE timesheet SET wh_status='已入账',fin_approver=?,fin_approve_time=? WHERE id=?",
                           (user.get("display_name",""), datetime.now().isoformat(), tid))
        db.commit()
        return {"ok": True}
    except Exception as e:
        db.rollback()
        raise HTTPException(500, f"批量审批失败: {str(e)}")
    finally:
        db.close()

# ── Containers ──
@app.get("/api/containers")
def get_containers(user=Depends(get_user)): return q("container_records")

@app.post("/api/containers")
async def create_container(request: Request, user=Depends(get_user)):
    data = await request.json()
    if "id" not in data: data["id"] = f"CT-{uuid.uuid4().hex[:6]}"
    
    # Calculate duration with validation
    if data.get("start_time") and data.get("end_time"):
        try:
            sh, sm = map(int, data["start_time"].split(":"))
            eh, em = map(int, data["end_time"].split(":"))
            mins = (eh*60+em)-(sh*60+sm)
            if mins < 0: mins += 1440
            data["duration_minutes"] = mins
        except (ValueError, AttributeError) as e:
            # Invalid time format - raise error for user feedback
            raise HTTPException(400, f"无效的时间格式: {data.get('start_time')} - {data.get('end_time')}")

    # 根据仓库获取装卸柜薪资
    wh = data.get("warehouse_code")
    container_type = data.get("container_type", "40GP")

    if wh:
        db = database.get_db()
        wh_info = db.execute("SELECT * FROM warehouses WHERE code=?", (wh,)).fetchone()
        if wh_info:
            rate_map = {"20GP": "rate_20gp", "40GP": "rate_40gp", "45HC": "rate_45hc"}
            rate_col = rate_map.get(container_type, "rate_40gp")
            data["client_revenue"] = wh_info[rate_col] if wh_info.get(rate_col) else 0
        db.close()

    insert("container_records", data); return {"ok": True}

# ── Grades ──
@app.get("/api/grades")
def get_grades(user=Depends(get_user)): return q("grade_levels", order="series ASC, level ASC")

@app.get("/api/grade-evaluations")
def get_evaluations(user=Depends(get_user)): return q("grade_evaluations")

@app.post("/api/grade-evaluations")
async def create_eval(request: Request, user=Depends(get_user)):
    data = await request.json(); data["id"] = f"GE-{uuid.uuid4().hex[:6]}"
    insert("grade_evaluations", data); return {"ok": True}

# ── Promotions ──
@app.get("/api/promotions")
def get_promotions(user=Depends(get_user)): return q("promotion_applications")

@app.post("/api/promotions")
async def create_promotion(request: Request, user=Depends(get_user)):
    data = await request.json(); data["id"] = f"PA-{uuid.uuid4().hex[:6]}"
    data["apply_date"] = datetime.now().strftime("%Y-%m-%d")
    insert("promotion_applications", data); return {"ok": True}

@app.put("/api/promotions/{pid}")
async def update_promotion(pid: str, request: Request, user=Depends(get_user)):
    update("promotion_applications", "id", pid, await request.json()); return {"ok": True}

# ── Bonuses ──
@app.get("/api/bonuses")
def get_bonuses(user=Depends(get_user)): return q("bonus_applications")

@app.post("/api/bonuses")
async def create_bonus(request: Request, user=Depends(get_user)):
    data = await request.json(); data["id"] = f"BA-{uuid.uuid4().hex[:6]}"
    insert("bonus_applications", data); return {"ok": True}

@app.put("/api/bonuses/{bid}")
async def update_bonus(bid: str, request: Request, user=Depends(get_user)):
    update("bonus_applications", "id", bid, await request.json()); return {"ok": True}

# ── Performance ──
@app.get("/api/performance")
def get_performance(user=Depends(get_user)): return q("performance_reviews")

@app.post("/api/performance")
async def create_perf(request: Request, user=Depends(get_user)):
    data = await request.json(); data["id"] = f"PR-{uuid.uuid4().hex[:6]}"
    insert("performance_reviews", data); return {"ok": True}

@app.put("/api/performance/{pid}")
async def update_perf(pid: str, request: Request, user=Depends(get_user)):
    update("performance_reviews", "id", pid, await request.json()); return {"ok": True}

# ── Quotations ──
@app.get("/api/quotation-templates")
def get_qt(user=Depends(get_user)): return q("quotation_templates")

@app.get("/api/quotations")
def get_quotations(user=Depends(get_user)): return q("quotation_records")

@app.post("/api/quotations")
async def create_quotation(request: Request, user=Depends(get_user)):
    data = await request.json(); data["id"] = f"QR-{uuid.uuid4().hex[:6]}"
    data["quote_date"] = datetime.now().strftime("%Y-%m-%d")
    insert("quotation_records", data); return {"ok": True}

@app.put("/api/quotations/{qid}")
async def update_quotation(qid: str, request: Request, user=Depends(get_user)):
    update("quotation_records", "id", qid, await request.json()); return {"ok": True}

# ── Employee Files ──
@app.get("/api/files")
def get_files(employee_id: Optional[str] = None, user=Depends(get_user)):
    if employee_id: return q("employee_files", "employee_id=?", (employee_id,))
    return q("employee_files")

@app.post("/api/files")
async def create_file_rec(request: Request, user=Depends(get_user)):
    data = await request.json(); data["id"] = f"EF-{uuid.uuid4().hex[:6]}"
    data["upload_date"] = datetime.now().strftime("%Y-%m-%d")
    insert("employee_files", data); return {"ok": True}

# ── Leave ──
@app.get("/api/leave-types")
def get_lt(user=Depends(get_user)): return q("leave_types", order="code ASC")

@app.get("/api/leave-balances")
def get_lb(employee_id: Optional[str] = None, user=Depends(get_user)):
    if employee_id: return q("leave_balances", "employee_id=?", (employee_id,))
    return q("leave_balances", order="employee_id ASC")

@app.get("/api/leave-requests")
def get_lr(user=Depends(get_user)): return q("leave_requests")

@app.post("/api/leave-requests")
async def create_lr(request: Request, user=Depends(get_user)):
    data = await request.json(); data["id"] = f"LR-{uuid.uuid4().hex[:6]}"
    data["apply_date"] = datetime.now().strftime("%Y-%m-%d"); data["status"] = "已提交"
    insert("leave_requests", data); return {"ok": True}

@app.put("/api/leave-requests/{lid}")
async def update_lr(lid: str, request: Request, user=Depends(get_user)):
    data = await request.json()
    update("leave_requests", "id", lid, data)
    if data.get("status") == "已批准":
        lr = q("leave_requests", "id=?", (lid,))
        if lr:
            current_year = get_current_year()
            db = database.get_db()
            db.execute("UPDATE leave_balances SET used_days=used_days+?,remaining_days=remaining_days-? WHERE employee_id=? AND year=? AND leave_type=?",
                (lr[0]["days"], lr[0]["days"], lr[0]["employee_id"], current_year, lr[0]["leave_type"]))
            db.commit(); db.close()
    return {"ok": True}

# ── Expenses ──
@app.get("/api/expenses")
def get_expenses(user=Depends(get_user)): return q("expense_claims")

@app.post("/api/expenses")
async def create_expense(request: Request, user=Depends(get_user)):
    data = await request.json(); data["id"] = f"EC-{uuid.uuid4().hex[:6]}"
    data["apply_date"] = datetime.now().strftime("%Y-%m-%d"); data["status"] = "已提交"
    insert("expense_claims", data); return {"ok": True}

@app.put("/api/expenses/{eid}")
async def update_expense(eid: str, request: Request, user=Depends(get_user)):
    update("expense_claims", "id", eid, await request.json()); return {"ok": True}

# ── Other modules ──
@app.get("/api/talent")
def get_talent(user=Depends(get_user)): return q("talent_pool")

@app.get("/api/dispatch")
def get_dispatch(user=Depends(get_user)): return q("dispatch_needs")

@app.get("/api/recruit")
def get_recruit(user=Depends(get_user)): return q("recruit_progress")

@app.get("/api/schedules")
def get_schedules(user=Depends(get_user)): return q("schedules", order="work_date ASC")

@app.get("/api/messages")
def get_messages(user=Depends(get_user)): return q("messages", order="timestamp DESC")

@app.get("/api/logs")
def get_logs(user=Depends(get_user)): return q("audit_logs", order="id DESC", limit=200)

# ── Settlement ──
@app.get("/api/settlement")
def get_settlement(mode: str = "own", user=Depends(get_user)):
    db = database.get_db()
    if mode == "own":
        rows = db.execute("SELECT employee_id,employee_name,grade,warehouse_code,SUM(hours) h,SUM(hourly_pay) pay,SUM(ssi_deduct) ssi,SUM(tax_deduct) tax,SUM(net_pay) net FROM timesheet WHERE source='自有' GROUP BY employee_id").fetchall()
    elif mode == "supplier":
        rows = db.execute("SELECT supplier_id,warehouse_code,COUNT(DISTINCT employee_id) hc,SUM(hours) h,SUM(hourly_pay) pay FROM timesheet WHERE source='供应商' GROUP BY supplier_id").fetchall()
    else:
        rows = db.execute("SELECT warehouse_code,COUNT(DISTINCT employee_id) hc,SUM(hours) h,SUM(hourly_pay) cost FROM timesheet GROUP BY warehouse_code").fetchall()
    db.close(); return [dict(r) for r in rows]

# ── Dashboard ──
@app.get("/api/analytics/dashboard")
def dashboard(user=Depends(get_user)):
    db = database.get_db()
    current_year_month = get_current_year_month()
    r = {
        "total_emp": db.execute("SELECT COUNT(*) FROM employees WHERE status='在职'").fetchone()[0],
        "own": db.execute("SELECT COUNT(*) FROM employees WHERE source='自有' AND status='在职'").fetchone()[0],
        "supplier": db.execute("SELECT COUNT(*) FROM employees WHERE source='供应商' AND status='在职'").fetchone()[0],
        "wh_count": db.execute("SELECT COUNT(*) FROM warehouses").fetchone()[0],
        "pending_leave": db.execute("SELECT COUNT(*) FROM leave_requests WHERE status='待审批'").fetchone()[0],
        "pending_expense": db.execute("SELECT COUNT(*) FROM expense_claims WHERE status IN ('已提交','待审批')").fetchone()[0],
        "pending_ts": db.execute("SELECT COUNT(*) FROM timesheet WHERE wh_status='待仓库审批'").fetchone()[0],
        "monthly_hrs": db.execute("SELECT COALESCE(SUM(hours),0) FROM timesheet WHERE work_date LIKE ?", (f"{current_year_month}%",)).fetchone()[0],
        "grade_dist": [dict(r) for r in db.execute("SELECT grade,COUNT(*) c FROM employees WHERE status='在职' GROUP BY grade ORDER BY grade").fetchall()],
        "wh_dist": [dict(r) for r in db.execute("SELECT primary_wh w,COUNT(*) c FROM employees WHERE status='在职' GROUP BY primary_wh").fetchall()],
    }
    db.close(); return r

# ── Permissions ──
@app.get("/api/permissions")
def get_perms(user=Depends(get_user)): return q("permission_overrides", order="role ASC, module ASC")

@app.post("/api/permissions/update")
async def update_perm(request: Request, user=Depends(get_user)):
    d = await request.json(); db = database.get_db()
    db.execute("UPDATE permission_overrides SET can_view=?,can_create=?,can_edit=?,can_delete=?,can_export=?,can_approve=? WHERE role=? AND module=?",
        (d.get("can_view",0),d.get("can_create",0),d.get("can_edit",0),d.get("can_delete",0),d.get("can_export",0),d.get("can_approve",0),d["role"],d["module"]))
    db.commit(); db.close(); return {"ok": True}

# ── File Upload ──
@app.post("/api/upload")
async def upload_file(file: UploadFile = File(...), category: str = Form("general")):
    ext = os.path.splitext(file.filename)[1]
    fname = f"{category}_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}{ext}"
    path = os.path.join(UPLOAD_DIR, fname)
    content = await file.read()
    with open(path, "wb") as f: f.write(content)
    return {"filename": fname, "url": f"/uploads/{fname}", "size": len(content)}

# ── PWA Manifest ──
@app.get("/manifest.json")
def manifest():
    return JSONResponse({"name":"渊博579 HR系统","short_name":"HR V6","start_url":"/","display":"standalone",
        "background_color":"#0f172a","theme_color":"#4f6ef7","orientation":"any",
        "icons":[{"src":"/api/icon/192","sizes":"192x192","type":"image/svg+xml"},
                 {"src":"/api/icon/512","sizes":"512x512","type":"image/svg+xml"}]})

@app.get("/api/icon/{size}")
def icon(size: int):
    svg = f'<svg xmlns="http://www.w3.org/2000/svg" width="{size}" height="{size}"><rect width="{size}" height="{size}" rx="{size//8}" fill="#4f6ef7"/><text x="50%" y="55%" text-anchor="middle" dominant-baseline="middle" fill="#fff" font-family="Arial" font-size="{size//3}" font-weight="bold">HR</text></svg>'
    from fastapi.responses import Response
    return Response(content=svg, media_type="image/svg+xml")

# ── Static Files & SPA ──
app.mount("/uploads", StaticFiles(directory=UPLOAD_DIR), name="uploads")

@app.get("/{path:path}")
def spa(path: str):
    fp = os.path.join(STATIC_DIR, path)
    if path and os.path.isfile(fp): return FileResponse(fp)

    # 兼容部署时前端文件位于项目根目录（如 Railway）
    root_fp = os.path.join(os.path.dirname(__file__), path)
    if path and os.path.isfile(root_fp):
        return FileResponse(root_fp)

    idx = os.path.join(STATIC_DIR, "index.html")
    if os.path.isfile(idx): return FileResponse(idx)

    root_idx = os.path.join(os.path.dirname(__file__), "index.html")
    if os.path.isfile(root_idx):
        return FileResponse(root_idx)

    return JSONResponse({"msg": "渊博579 HR V6 API running"})

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8080))

    # Configure uvicorn logging to use stdout instead of stderr.
    # This prevents deployment platforms (e.g., Railway) from tagging
    # INFO-level lifecycle messages (startup/shutdown) as errors.
    log_config = copy.deepcopy(uvicorn.config.LOGGING_CONFIG)
    log_config["handlers"]["default"]["stream"] = "ext://sys.stdout"
    log_config["handlers"]["access"]["stream"] = "ext://sys.stdout"

    uvicorn.run(app, host="0.0.0.0", port=port, log_config=log_config)
