"""渊博+579 HR V6 — FastAPI Backend (Enhanced with Account Management & Warehouse Salary)"""
import os, json, uuid, shutil, secrets, string, traceback, threading, logging, sys, copy, time, hashlib, hmac, base64
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from fastapi import FastAPI, HTTPException, Depends, UploadFile, File, Form, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
import database
import re

UPLOAD_DIR = os.path.join(os.path.dirname(__file__), "uploads")
STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(STATIC_DIR, exist_ok=True)

# German labor law compliance limits (ArbZG)
MAX_DAILY_HOURS = 10   # §3 ArbZG: max 10 hours per day
MAX_WEEKLY_HOURS = 48   # §3 ArbZG: max 48 hours per week (average)

_db_ready = False

DB_INIT_MAX_RETRIES = int(os.environ.get("DB_INIT_MAX_RETRIES", 5))
DB_INIT_RETRY_DELAY = int(os.environ.get("DB_INIT_RETRY_DELAY", 3))

def _init_database():
    global _db_ready
    for attempt in range(1, DB_INIT_MAX_RETRIES + 1):
        try:
            database.init_db()
            database.seed_data()
            database.ensure_demo_users()
            _db_ready = True
            print("✅ Database initialized successfully")
            return
        except Exception as e:
            print(f"⚠️ Database initialization error (attempt {attempt}/{DB_INIT_MAX_RETRIES}): {e}")
            if attempt < DB_INIT_MAX_RETRIES:
                time.sleep(DB_INIT_RETRY_DELAY)
            else:
                traceback.print_exc()

@asynccontextmanager
async def lifespan(app):
    threading.Thread(target=_init_database, daemon=True).start()
    yield
    logging.getLogger("uvicorn.error").info("Application shutting down gracefully")

app = FastAPI(title="渊博579 HR V6", lifespan=lifespan)
# CORS: Restrict to specific origins in production. Use "*" only for development.
ALLOWED_ORIGINS = os.environ.get("ALLOWED_ORIGINS", "*").split(",")
app.add_middleware(
    CORSMiddleware, 
    allow_origins=ALLOWED_ORIGINS, 
    allow_credentials=True, 
    allow_methods=["*"], 
    allow_headers=["*"]
)

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
    "schedules", "messages", "permission_overrides", "enterprise_documents",
    "safety_incidents", "id_naming_rules", "payslips", "payroll_confirmations",
    "dispatch_transfers"
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
    "enterprise_documents": ["id", "created_at", "updated_at", "category", "title"],
    "safety_incidents": ["id", "created_at", "updated_at", "incident_date", "status"],
    "id_naming_rules": ["id", "updated_at"],
    "payslips": ["id", "created_at", "month", "employee_id"],
    "payroll_confirmations": ["id", "created_at", "month"],
    "dispatch_transfers": ["id", "created_at", "dispatch_date"],
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
    user_info = {"username": u["username"], "display_name": u["display_name"], "role": u["role"], "employee_id": u["employee_id"]}
    if u["supplier_id"]:
        user_info["supplier_id"] = u["supplier_id"]
    if u["warehouse_code"]:
        user_info["warehouse_code"] = u["warehouse_code"]
    return {"token": token, "user": user_info}

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
def get_employees(user=Depends(get_user)):
    role = user.get("role", "worker")
    # Supplier users can only see their own workers
    if role == "sup" and user.get("supplier_id"):
        rows = q("employees", "supplier_id=?", (user["supplier_id"],))
        return _filter_hidden_fields(rows, role, "employees")
    # Warehouse users can only see employees in their warehouse
    if role == "wh" and user.get("warehouse_code"):
        wh = user["warehouse_code"]
        db = database.get_db()
        rows = db.execute(
            "SELECT * FROM employees WHERE primary_wh=? OR dispatch_whs LIKE ?",
            (wh, f"%{wh}%")
        ).fetchall()
        db.close()
        rows = [dict(r) for r in rows]
        return _filter_hidden_fields(rows, role, "employees")
    rows = q("employees")
    return _filter_hidden_fields(rows, role, "employees")

@app.get("/api/employees/{eid}")
def get_employee(eid: str, user=Depends(get_user)):
    emps = q("employees", "id=?", (eid,))
    if not emps: raise HTTPException(404, "员工不存在")
    role = user.get("role", "worker")
    filtered = _filter_hidden_fields(emps, role, "employees")
    return filtered[0]

@app.post("/api/employees")
async def create_employee(request: Request, user=Depends(get_user)):
    data = await request.json()
    if not data.get("name"):
        raise HTTPException(400, "员工姓名不能为空")
    # Extract account creation fields before inserting employee
    create_account = data.pop("create_account", False)
    account_role = data.pop("account_role", "worker")
    if "id" not in data: data["id"] = f"YB-{uuid.uuid4().hex[:6].upper()}"
    data.setdefault("created_at", datetime.now().isoformat())
    data.setdefault("updated_at", datetime.now().isoformat())
    if create_account:
        data["has_account"] = 1
    try:
        insert("employees", data)
    except Exception as e:
        raise HTTPException(500, f"创建员工失败: {str(e)}")
    audit_log(user.get("username", ""), "create", "employees", data["id"], f"创建员工: {data.get('name','')}")
    result = {"ok": True, "id": data["id"]}
    # Optionally create a system account for the new employee
    if create_account:
        VALID_ROLES = {"admin", "ceo", "mgr", "hr", "fin", "wh", "sup", "worker"}
        if account_role not in VALID_ROLES:
            account_role = "worker"
        employee_id = data["id"]
        username = employee_id.lower().replace("-", "")
        password = generate_password(8)
        password_hash = hash_password(password)
        db = database.get_db()
        try:
            db.execute(
                """INSERT INTO users(username, password_hash, display_name, role, employee_id, warehouse_code, biz_line)
                   VALUES(?,?,?,?,?,?,?)""",
                (username, password_hash, data.get("name", ""), account_role,
                 employee_id, data.get("primary_wh", ""), data.get("biz_line", "")))
            db.commit()
        except Exception as e:
            # Revert has_account flag since account creation failed
            try:
                db.execute("UPDATE employees SET has_account=0 WHERE id=?", (employee_id,))
                db.commit()
            except Exception:
                pass
            raise HTTPException(500, f"创建账号失败: {str(e)}")
        finally:
            db.close()
        audit_log(user.get("username", ""), "generate_account", "users", username,
                  f"创建员工时同步生成账号, 角色: {account_role}")
        result["account"] = {"username": username, "password": password, "role": account_role}
    return result

@app.put("/api/employees/{eid}")
async def update_employee(eid: str, request: Request, user=Depends(get_user)):
    data = await request.json(); data["updated_at"] = datetime.now().isoformat()
    role = user.get("role", "worker")
    data = _enforce_editable_fields(data, role, "employees")
    if not data:
        raise HTTPException(403, "无可编辑字段")
    try:
        update("employees", "id", eid, data)
    except Exception as e:
        raise HTTPException(500, f"更新员工失败: {str(e)}")
    audit_log(user.get("username", ""), "update", "employees", eid, json.dumps(list(data.keys())))
    return {"ok": True}

# ── Employee Roster (花名册) ──
@app.get("/api/roster")
def get_roster(
    status: Optional[str] = None,
    dispatch_type: Optional[str] = None,
    warehouse_code: Optional[str] = None,
    source: Optional[str] = None,
    user=Depends(get_user)
):
    """花名册接口 - 获取员工花名册列表，支持按状态、派遣类型、仓库、来源筛选"""
    role = user.get("role", "worker")
    conditions = []
    params = []
    # Data scope filtering for supplier users
    if role == "sup" and user.get("supplier_id"):
        conditions.append("e.supplier_id=?")
        params.append(user["supplier_id"])
    # Data scope filtering for warehouse users
    if role == "wh" and user.get("warehouse_code"):
        wh = user["warehouse_code"]
        conditions.append("(e.primary_wh=? OR e.dispatch_whs LIKE ?)")
        params.extend([wh, f"%{wh}%"])
    if status:
        conditions.append("e.status=?")
        params.append(status)
    if dispatch_type:
        conditions.append("e.dispatch_type=?")
        params.append(dispatch_type)
    if warehouse_code:
        conditions.append("(e.primary_wh=? OR e.dispatch_whs LIKE ?)")
        params.extend([warehouse_code, f"%{warehouse_code}%"])
    if source:
        conditions.append("e.source=?")
        params.append(source)
    where = " AND ".join(conditions) if conditions else "1=1"

    db = database.get_db()
    rows = db.execute(f"""
        SELECT e.*, s.name as supplier_name, w.name as warehouse_name, w.service_type
        FROM employees e
        LEFT JOIN suppliers s ON s.id = e.supplier_id
        LEFT JOIN warehouses w ON w.code = e.primary_wh
        WHERE {where}
        ORDER BY e.id ASC
    """, tuple(params)).fetchall()
    db.close()
    result = [dict(r) for r in rows]
    return _filter_hidden_fields(result, role, "employees")

@app.get("/api/roster/stats")
def get_roster_stats(user=Depends(get_user)):
    """花名册统计 - 按派遣类型、合同类型、来源等统计"""
    db = database.get_db()
    stats = {
        "by_dispatch_type": [dict(r) for r in db.execute(
            "SELECT dispatch_type, COUNT(*) as count FROM employees WHERE status='在职' AND dispatch_type IS NOT NULL GROUP BY dispatch_type"
        ).fetchall()],
        "by_contract_type": [dict(r) for r in db.execute(
            "SELECT contract_type, COUNT(*) as count FROM employees WHERE status='在职' GROUP BY contract_type"
        ).fetchall()],
        "by_source": [dict(r) for r in db.execute(
            "SELECT source, COUNT(*) as count FROM employees WHERE status='在职' GROUP BY source"
        ).fetchall()],
        "by_nationality": [dict(r) for r in db.execute(
            "SELECT nationality, COUNT(*) as count FROM employees WHERE status='在职' GROUP BY nationality"
        ).fetchall()],
        "contract_expiring_soon": [dict(r) for r in db.execute(
            "SELECT id, name, contract_end, primary_wh FROM employees WHERE status='在职' AND contract_end IS NOT NULL AND contract_end <= date('now', '+90 days') ORDER BY contract_end ASC"
        ).fetchall()],
        "work_permit_expiring_soon": [dict(r) for r in db.execute(
            "SELECT id, name, work_permit_expiry, nationality FROM employees WHERE status='在职' AND work_permit_expiry IS NOT NULL AND work_permit_expiry <= date('now', '+90 days') ORDER BY work_permit_expiry ASC"
        ).fetchall()],
    }
    db.close()
    return stats

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
    if user.get("role") not in ["admin", "hr", "mgr", "ceo"]:
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
    """创建仓库薪资配置 - P7+对自己仓库, P8+对区域, P9+/admin/ceo全部"""
    role = user.get("role", "worker")
    data = await request.json()
    if not data.get("warehouse_code") or not data.get("grade"):
        raise HTTPException(400, "仓库编码和职级不能为空")
    # Grade-based salary scope check
    if role not in ("admin", "ceo"):
        grade = _get_employee_grade(user)
        gp = _get_grade_permissions(grade)
        salary_scope = gp["salary_scope"]
        if salary_scope == "none" or salary_scope == "suggest":
            raise HTTPException(403, "当前职级无薪资配置修改权限 / Insufficient grade for salary config modification")
        if salary_scope == "own_warehouse":
            wh = _get_employee_warehouse(user)
            if data["warehouse_code"] != wh:
                raise HTTPException(403, "仅可配置本仓库薪资 / Can only configure salary for own warehouse")
        if salary_scope == "regional":
            wh = _get_employee_warehouse(user)
            region_whs = _get_region_warehouses(wh) if wh else []
            if data["warehouse_code"] not in region_whs:
                raise HTTPException(403, "仅可配置本区域仓库薪资 / Can only configure salary for regional warehouses")
    data["id"] = f"WSC-{data['warehouse_code']}-{data['grade']}-{data.get('position_type','库内')}"
    data["created_at"] = datetime.now().isoformat()
    data["updated_at"] = datetime.now().isoformat()
    try:
        insert("warehouse_salary_config", data)
    except Exception as e:
        raise HTTPException(500, f"创建仓库薪资配置失败: {str(e)}")
    audit_log(user.get("username", ""), "create", "warehouse_salary_config", data["id"], f"仓库: {data['warehouse_code']}, 职级: {data['grade']}")
    return {"ok": True, "id": data["id"]}

@app.put("/api/warehouse-salary-config/{config_id}")
async def update_wh_salary_config(config_id: str, request: Request, user=Depends(get_user)):
    """更新仓库薪资配置 - P7+对自己仓库, P8+对区域, P9+/admin/ceo全部"""
    role = user.get("role", "worker")
    data = await request.json()
    data["updated_at"] = datetime.now().isoformat()
    # Grade-based salary scope check
    if role not in ("admin", "ceo"):
        grade = _get_employee_grade(user)
        gp = _get_grade_permissions(grade)
        salary_scope = gp["salary_scope"]
        if salary_scope == "none" or salary_scope == "suggest":
            raise HTTPException(403, "当前职级无薪资配置修改权限 / Insufficient grade for salary config modification")
        # Check target warehouse from config_id (format: WSC-{warehouse_code}-{grade}-{position})
        db = database.get_db()
        cfg = db.execute("SELECT warehouse_code FROM warehouse_salary_config WHERE id=?", (config_id,)).fetchone()
        db.close()
        if cfg:
            target_wh = cfg["warehouse_code"]
            if salary_scope == "own_warehouse":
                wh = _get_employee_warehouse(user)
                if target_wh != wh:
                    raise HTTPException(403, "仅可修改本仓库薪资配置 / Can only modify salary config for own warehouse")
            if salary_scope == "regional":
                wh = _get_employee_warehouse(user)
                region_whs = _get_region_warehouses(wh) if wh else []
                if target_wh not in region_whs:
                    raise HTTPException(403, "仅可修改本区域仓库薪资配置 / Can only modify salary config for regional warehouses")
    try:
        update("warehouse_salary_config", "id", config_id, data)
    except Exception as e:
        raise HTTPException(500, f"更新仓库薪资配置失败: {str(e)}")
    audit_log(user.get("username", ""), "update", "warehouse_salary_config", config_id, json.dumps(list(data.keys())))
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
    if not data.get("name"):
        raise HTTPException(400, "供应商名称不能为空")
    if "id" not in data: data["id"] = f"SUP-{uuid.uuid4().hex[:4].upper()}"
    data.setdefault("created_at", datetime.now().isoformat())
    data.setdefault("updated_at", datetime.now().isoformat())
    try:
        insert("suppliers", data)
    except Exception as e:
        raise HTTPException(500, f"创建供应商失败: {str(e)}")
    audit_log(user.get("username", ""), "create", "suppliers", data["id"], f"创建供应商: {data.get('name','')}")
    return {"ok": True, "id": data["id"]}

@app.put("/api/suppliers/{sid}")
async def update_supplier(sid: str, request: Request, user=Depends(get_user)):
    """更新供应商信息"""
    data = await request.json()
    data.pop("id", None)
    data["updated_at"] = datetime.now().isoformat()
    try:
        update("suppliers", "id", sid, data)
    except Exception as e:
        raise HTTPException(500, f"更新供应商失败: {str(e)}")
    audit_log(user.get("username", ""), "update", "suppliers", sid, json.dumps(list(data.keys())))
    return {"ok": True}

@app.get("/api/suppliers/{sid}")
def get_supplier(sid: str, user=Depends(get_user)):
    """获取单个供应商详情"""
    sups = q("suppliers", "id=?", (sid,))
    if not sups:
        raise HTTPException(404, "供应商不存在")
    return sups[0]

@app.get("/api/supplier/worker-activities")
def get_supplier_worker_activities(user=Depends(get_user)):
    """获取供应商旗下所有工人的动态信息（工时、排班、出勤、请假等）
    Supplier users see activities for their own workers;
    Admin/HR/CEO/MGR can specify supplier_id as query param."""
    role = user.get("role", "worker")
    supplier_id = user.get("supplier_id")

    # Non-supplier users with sufficient permissions can view any supplier's workers
    if role in ("admin", "ceo", "hr", "mgr"):
        # Allow admin/ceo/hr/mgr to view any supplier
        supplier_id = supplier_id  # they see all if no supplier_id bound
    elif role == "sup":
        if not supplier_id:
            raise HTTPException(403, "供应商账号未关联供应商")
    else:
        raise HTTPException(403, "无权限查看供应商工人动态")

    db = database.get_db()

    # Get supplier's workers
    if supplier_id:
        workers = db.execute(
            "SELECT id, name, grade, position, primary_wh, status, phone FROM employees WHERE supplier_id=? ORDER BY primary_wh, grade",
            (supplier_id,)
        ).fetchall()
    else:
        workers = db.execute(
            "SELECT id, name, grade, position, primary_wh, status, supplier_id, phone FROM employees WHERE source='供应商' ORDER BY supplier_id, primary_wh, grade"
        ).fetchall()

    worker_ids = [w["id"] for w in workers]
    if not worker_ids:
        db.close()
        return {"workers": [], "timesheet": [], "leave_requests": [], "schedules": [], "summary": {}}

    placeholders = ",".join(["?"] * len(worker_ids))

    # Recent timesheet entries (last 30 days)
    timesheet = db.execute(
        f"SELECT * FROM timesheet WHERE employee_id IN ({placeholders}) AND work_date >= date('now', '-30 days') ORDER BY work_date DESC",
        tuple(worker_ids)
    ).fetchall()

    # Active leave requests
    leave_requests = db.execute(
        f"SELECT * FROM leave_requests WHERE employee_id IN ({placeholders}) ORDER BY start_date DESC",
        tuple(worker_ids)
    ).fetchall()

    # Upcoming schedules
    schedules = db.execute(
        f"SELECT * FROM schedules WHERE employee_id IN ({placeholders}) AND work_date >= date('now') ORDER BY work_date ASC",
        tuple(worker_ids)
    ).fetchall()

    # Summary statistics
    current_month = get_current_year_month()
    summary = {
        "total_workers": len(workers),
        "active_workers": sum(1 for w in workers if w["status"] == "在职"),
        "monthly_hours": db.execute(
            f"SELECT COALESCE(SUM(hours),0) FROM timesheet WHERE employee_id IN ({placeholders}) AND work_date LIKE ?",
            tuple(worker_ids) + (f"{current_month}%",)
        ).fetchone()[0],
        "pending_leave": sum(1 for lr in leave_requests if lr["status"] == "待审批"),
        "by_warehouse": [dict(r) for r in db.execute(
            f"SELECT primary_wh, COUNT(*) c FROM employees WHERE id IN ({placeholders}) AND status='在职' GROUP BY primary_wh",
            tuple(worker_ids)
        ).fetchall()],
        "by_grade": [dict(r) for r in db.execute(
            f"SELECT grade, COUNT(*) c FROM employees WHERE id IN ({placeholders}) AND status='在职' GROUP BY grade",
            tuple(worker_ids)
        ).fetchall()],
    }

    db.close()
    return {
        "workers": [dict(w) for w in workers],
        "timesheet": [dict(t) for t in timesheet],
        "leave_requests": [dict(lr) for lr in leave_requests],
        "schedules": [dict(s) for s in schedules],
        "summary": summary,
    }

# ── Warehouses ──
@app.get("/api/warehouses")
def get_warehouses(user=Depends(get_user)): return q("warehouses", order="code ASC")

@app.post("/api/warehouses")
async def create_warehouse(request: Request, user=Depends(get_user)):
    data = await request.json()
    if not data.get("code") or not data.get("name"):
        raise HTTPException(400, "仓库编码和名称不能为空")
    data.setdefault("created_at", datetime.now().isoformat())
    data.setdefault("updated_at", datetime.now().isoformat())
    try:
        insert("warehouses", data)
    except Exception as e:
        raise HTTPException(500, f"创建仓库失败: {str(e)}")
    audit_log(user.get("username", ""), "create", "warehouses", data["code"], f"创建仓库: {data.get('name','')}")
    return {"ok": True, "code": data["code"]}

@app.put("/api/warehouses/{code}")
async def update_warehouse(code: str, request: Request, user=Depends(get_user)):
    data = await request.json()
    data.pop("code", None)
    data["updated_at"] = datetime.now().isoformat()
    try:
        update("warehouses", "code", code, data)
    except Exception as e:
        raise HTTPException(500, f"更新仓库失败: {str(e)}")
    audit_log(user.get("username", ""), "update", "warehouses", code, json.dumps(list(data.keys())))
    return {"ok": True}

# ── Enterprise Documents ──
@app.get("/api/enterprise-docs")
def get_enterprise_docs(category: Optional[str] = None, warehouse_code: Optional[str] = None, user=Depends(get_user)):
    conditions = []
    params = []
    if category:
        conditions.append("category=?")
        params.append(category)
    if warehouse_code:
        conditions.append("(warehouse_code=? OR warehouse_code IS NULL OR warehouse_code='')")
        params.append(warehouse_code)
    where = " AND ".join(conditions) if conditions else "1=1"
    return q("enterprise_documents", where, tuple(params), order="created_at DESC")

@app.post("/api/enterprise-docs")
async def create_enterprise_doc(request: Request, user=Depends(get_user)):
    data = await request.json()
    if not data.get("title"):
        raise HTTPException(400, "文档标题不能为空")
    data["id"] = f"ED-{uuid.uuid4().hex[:10]}"
    data.setdefault("category", "通用")
    data.setdefault("status", "已发布")
    data.setdefault("uploaded_by", user.get("display_name", ""))
    data.setdefault("created_at", datetime.now().isoformat())
    data.setdefault("updated_at", datetime.now().isoformat())
    try:
        insert("enterprise_documents", data)
    except Exception as e:
        raise HTTPException(500, f"创建企业文档失败: {str(e)}")
    audit_log(user.get("username", ""), "create", "enterprise_documents", data["id"], f"文档: {data.get('title','')}")
    return {"ok": True, "id": data["id"]}

@app.put("/api/enterprise-docs/{doc_id}")
async def update_enterprise_doc(doc_id: str, request: Request, user=Depends(get_user)):
    data = await request.json()
    data.pop("id", None)
    data["updated_at"] = datetime.now().isoformat()
    try:
        update("enterprise_documents", "id", doc_id, data)
    except Exception as e:
        raise HTTPException(500, f"更新企业文档失败: {str(e)}")
    audit_log(user.get("username", ""), "update", "enterprise_documents", doc_id, json.dumps(list(data.keys())))
    return {"ok": True}

# ── Timesheet ──
@app.get("/api/timesheet")
def get_timesheet(employee_id: Optional[str] = None, user=Depends(get_user)):
    role = user.get("role", "worker")
    if employee_id:
        return q("timesheet", "employee_id=?", (employee_id,), order="work_date DESC, employee_id ASC")
    # Supplier users see only their workers' timesheet
    if role == "sup" and user.get("supplier_id"):
        return q("timesheet", "supplier_id=?", (user["supplier_id"],), order="work_date DESC, employee_id ASC")
    # Warehouse users see only their warehouse timesheet
    if role == "wh" and user.get("warehouse_code"):
        return q("timesheet", "warehouse_code=?", (user["warehouse_code"],), order="work_date DESC, employee_id ASC")
    # Worker/mgr with employee_id: apply grade-based data scope
    if role in ("worker", "mgr") and user.get("employee_id"):
        scope = _check_grade_data_scope(user)
        if scope == "self_only":
            return q("timesheet", "employee_id=?", (user["employee_id"],), order="work_date DESC")
        if scope == "own_warehouse":
            wh = _get_employee_warehouse(user)
            if wh:
                return q("timesheet", "warehouse_code=?", (wh,), order="work_date DESC, employee_id ASC")
        if scope == "regional":
            wh = _get_employee_warehouse(user)
            region_whs = _get_region_warehouses(wh) if wh else []
            if region_whs:
                placeholders = ",".join(["?"] * len(region_whs))
                return q("timesheet", f"warehouse_code IN ({placeholders})", tuple(region_whs), order="work_date DESC, employee_id ASC")
    return q("timesheet", order="work_date DESC, employee_id ASC")

@app.post("/api/timesheet")
async def create_timesheet(request: Request, user=Depends(get_user)):
    data = await request.json()
    if not data.get("employee_id") or not data.get("work_date") or not data.get("warehouse_code"):
        raise HTTPException(400, "员工ID、工作日期和仓库编码不能为空")
    if "id" not in data: data["id"] = f"WT-{uuid.uuid4().hex[:8]}"

    # ── German labor law compliance checks ──
    hours = float(data.get("hours", 0))
    if hours > MAX_DAILY_HOURS:
        raise HTTPException(400, f"根据德国劳动法(ArbZG)，每日工作时间不得超过{MAX_DAILY_HOURS}小时 / Tägliche Arbeitszeit darf {MAX_DAILY_HOURS} Stunden nicht überschreiten")

    employee_id = data.get("employee_id")
    work_date = data.get("work_date")
    warehouse_code = data.get("warehouse_code")

    # Check weekly hours compliance (max 48h/week per German law)
    if employee_id and work_date:
        db = database.get_db()
        from datetime import date as dt_date
        parts = work_date.split("-")
        d = dt_date(int(parts[0]), int(parts[1]), int(parts[2]))
        week_start = (d - timedelta(days=d.weekday())).isoformat()
        week_end = (d + timedelta(days=6 - d.weekday())).isoformat()
        weekly = db.execute(
            "SELECT COALESCE(SUM(hours),0) as total FROM timesheet WHERE employee_id=? AND work_date>=? AND work_date<=?",
            (employee_id, week_start, week_end)
        ).fetchone()
        weekly_total = (weekly["total"] if weekly else 0) + hours
        db.close()
        if weekly_total > MAX_WEEKLY_HOURS:
            raise HTTPException(400, f"该员工本周已工作{weekly_total-hours}小时，加上本次{hours}小时共{weekly_total}小时，超过德国劳动法{MAX_WEEKLY_HOURS}小时/周上限 / Wöchentliche Arbeitszeit würde {MAX_WEEKLY_HOURS} Stunden überschreiten")

    # 检查是否已存在相同的工时记录
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

    data.setdefault("created_at", datetime.now().isoformat())
    data.setdefault("updated_at", datetime.now().isoformat())
    try:
        insert("timesheet", data)
    except Exception as e:
        raise HTTPException(500, f"创建工时记录失败: {str(e)}")
    audit_log(user.get("username", ""), "create", "timesheet", data["id"], f"员工: {employee_id}, 日期: {work_date}")
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
    """
    多级审批工时记录:
    type=leader  班组长审批: 待班组长审批 → 已班组长审批
    type=wh      驻仓经理审批: 已班组长审批 → 已仓库审批
    type=regional 区域经理审批: 已仓库审批 → 已区域审批
    type=fin     财务确认: 已区域审批 → 已入账
    """
    body = await request.json()
    db = database.get_db()
    approve_type = body.get("type", "wh")
    now_ts = datetime.now().isoformat()
    approver = user.get("display_name", "")
    try:
        for tid in body.get("ids", []):
            if approve_type == "leader":
                db.execute(
                    "UPDATE timesheet SET wh_status='已班组长审批',leader_approver=?,leader_approve_time=? WHERE id=?",
                    (approver, now_ts, tid))
            elif approve_type == "wh":
                db.execute(
                    "UPDATE timesheet SET wh_status='已仓库审批',wh_approver=?,wh_approve_time=? WHERE id=?",
                    (approver, now_ts, tid))
            elif approve_type == "regional":
                db.execute(
                    "UPDATE timesheet SET wh_status='已区域审批',regional_approver=?,regional_approve_time=? WHERE id=?",
                    (approver, now_ts, tid))
            else:
                db.execute(
                    "UPDATE timesheet SET wh_status='已入账',fin_approver=?,fin_approve_time=? WHERE id=?",
                    (approver, now_ts, tid))
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
            data["client_revenue"] = dict(wh_info).get(rate_col, 0) or 0
        db.close()

    insert("container_records", data)
    audit_log(user.get("username", ""), "create", "container_records", data["id"], f"柜号: {data.get('container_no','')}")
    return {"ok": True}

@app.put("/api/containers/{cid}")
async def update_container(cid: str, request: Request, user=Depends(get_user)):
    data = await request.json()
    if data.get("start_time") and data.get("end_time"):
        try:
            sh, sm = map(int, data["start_time"].split(":"))
            eh, em = map(int, data["end_time"].split(":"))
            mins = (eh*60+em)-(sh*60+sm)
            if mins < 0: mins += 1440
            data["duration_minutes"] = mins
        except (ValueError, AttributeError):
            raise HTTPException(400, f"无效的时间格式: {data.get('start_time')} - {data.get('end_time')}")
    try:
        update("container_records", "id", cid, data)
    except Exception as e:
        raise HTTPException(500, f"更新装卸柜记录失败: {str(e)}")
    audit_log(user.get("username", ""), "update", "container_records", cid, json.dumps(list(data.keys())))
    return {"ok": True}

# ── Grades ──
@app.get("/api/grades")
def get_grades(user=Depends(get_user)): return q("grade_levels", order="series ASC, level ASC")

@app.get("/api/grade-evaluations")
def get_evaluations(user=Depends(get_user)): return q("grade_evaluations")

@app.post("/api/grade-evaluations")
async def create_eval(request: Request, user=Depends(get_user)):
    data = await request.json()
    if not data.get("employee_id"):
        raise HTTPException(400, "员工ID不能为空")
    data["id"] = f"GE-{uuid.uuid4().hex[:6]}"
    data.setdefault("created_at", datetime.now().isoformat())
    try:
        insert("grade_evaluations", data)
    except Exception as e:
        raise HTTPException(500, f"创建职级评定失败: {str(e)}")
    audit_log(user.get("username", ""), "create", "grade_evaluations", data["id"], f"员工: {data.get('employee_id','')}")
    return {"ok": True}

# ── Promotions ──
@app.get("/api/promotions")
def get_promotions(user=Depends(get_user)): return q("promotion_applications")

@app.post("/api/promotions")
async def create_promotion(request: Request, user=Depends(get_user)):
    data = await request.json()
    if not data.get("employee_id"):
        raise HTTPException(400, "员工ID不能为空")
    data["id"] = f"PA-{uuid.uuid4().hex[:6]}"
    data["apply_date"] = datetime.now().strftime("%Y-%m-%d")
    data.setdefault("created_at", datetime.now().isoformat())
    try:
        insert("promotion_applications", data)
    except Exception as e:
        raise HTTPException(500, f"创建晋升申请失败: {str(e)}")
    audit_log(user.get("username", ""), "create", "promotion_applications", data["id"], f"员工: {data.get('employee_id','')}")
    return {"ok": True}

@app.put("/api/promotions/{pid}")
async def update_promotion(pid: str, request: Request, user=Depends(get_user)):
    data = await request.json()
    try:
        update("promotion_applications", "id", pid, data)
    except Exception as e:
        raise HTTPException(500, f"更新晋升申请失败: {str(e)}")
    audit_log(user.get("username", ""), "update", "promotion_applications", pid, json.dumps(list(data.keys())))
    return {"ok": True}

# ── Bonuses ──
@app.get("/api/bonuses")
def get_bonuses(user=Depends(get_user)): return q("bonus_applications")

@app.post("/api/bonuses")
async def create_bonus(request: Request, user=Depends(get_user)):
    data = await request.json()
    if not data.get("employee_id"):
        raise HTTPException(400, "员工ID不能为空")
    data["id"] = f"BA-{uuid.uuid4().hex[:6]}"
    data.setdefault("apply_date", datetime.now().strftime("%Y-%m-%d"))
    data.setdefault("created_at", datetime.now().isoformat())
    try:
        insert("bonus_applications", data)
    except Exception as e:
        raise HTTPException(500, f"创建奖金申请失败: {str(e)}")
    audit_log(user.get("username", ""), "create", "bonus_applications", data["id"], f"员工: {data.get('employee_id','')}")
    return {"ok": True}

@app.put("/api/bonuses/{bid}")
async def update_bonus(bid: str, request: Request, user=Depends(get_user)):
    data = await request.json()
    try:
        update("bonus_applications", "id", bid, data)
    except Exception as e:
        raise HTTPException(500, f"更新奖金申请失败: {str(e)}")
    audit_log(user.get("username", ""), "update", "bonus_applications", bid, json.dumps(list(data.keys())))
    return {"ok": True}

# ── Performance ──
@app.get("/api/performance")
def get_performance(user=Depends(get_user)): return q("performance_reviews")

@app.post("/api/performance")
async def create_perf(request: Request, user=Depends(get_user)):
    data = await request.json()
    if not data.get("employee_id"):
        raise HTTPException(400, "员工ID不能为空")
    data["id"] = f"PR-{uuid.uuid4().hex[:6]}"
    data.setdefault("created_at", datetime.now().isoformat())
    try:
        insert("performance_reviews", data)
    except Exception as e:
        raise HTTPException(500, f"创建绩效评估失败: {str(e)}")
    audit_log(user.get("username", ""), "create", "performance_reviews", data["id"], f"员工: {data.get('employee_id','')}")
    return {"ok": True}

@app.put("/api/performance/{pid}")
async def update_perf(pid: str, request: Request, user=Depends(get_user)):
    data = await request.json()
    try:
        update("performance_reviews", "id", pid, data)
    except Exception as e:
        raise HTTPException(500, f"更新绩效评估失败: {str(e)}")
    audit_log(user.get("username", ""), "update", "performance_reviews", pid, json.dumps(list(data.keys())))
    return {"ok": True}

# ── Quotations ──
@app.get("/api/quotation-templates")
def get_qt(user=Depends(get_user)): return q("quotation_templates")

@app.get("/api/quotations")
def get_quotations(user=Depends(get_user)): return q("quotation_records")

@app.post("/api/quotations")
async def create_quotation(request: Request, user=Depends(get_user)):
    data = await request.json()
    if not data.get("client_name"):
        raise HTTPException(400, "客户名称不能为空")
    data["id"] = f"QR-{uuid.uuid4().hex[:6]}"
    data["quote_date"] = datetime.now().strftime("%Y-%m-%d")
    data.setdefault("created_at", datetime.now().isoformat())
    try:
        insert("quotation_records", data)
    except Exception as e:
        raise HTTPException(500, f"创建报价失败: {str(e)}")
    audit_log(user.get("username", ""), "create", "quotation_records", data["id"], f"客户: {data.get('client_name','')}")
    return {"ok": True}

@app.put("/api/quotations/{qid}")
async def update_quotation(qid: str, request: Request, user=Depends(get_user)):
    data = await request.json()
    try:
        update("quotation_records", "id", qid, data)
    except Exception as e:
        raise HTTPException(500, f"更新报价失败: {str(e)}")
    audit_log(user.get("username", ""), "update", "quotation_records", qid, json.dumps(list(data.keys())))
    return {"ok": True}

# ── Employee Files ──
@app.get("/api/files")
def get_files(employee_id: Optional[str] = None, user=Depends(get_user)):
    if employee_id: return q("employee_files", "employee_id=?", (employee_id,))
    return q("employee_files")

@app.post("/api/files")
async def create_file_rec(request: Request, user=Depends(get_user)):
    data = await request.json()
    if not data.get("employee_id"):
        raise HTTPException(400, "员工ID不能为空")
    data["id"] = f"EF-{uuid.uuid4().hex[:6]}"
    data["upload_date"] = datetime.now().strftime("%Y-%m-%d")
    data.setdefault("uploaded_by", user.get("display_name", ""))
    data.setdefault("created_at", datetime.now().isoformat())
    try:
        insert("employee_files", data)
    except Exception as e:
        raise HTTPException(500, f"创建文件记录失败: {str(e)}")
    audit_log(user.get("username", ""), "create", "employee_files", data["id"], f"员工: {data.get('employee_id','')}")
    return {"ok": True}

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
    data = await request.json()
    if not data.get("employee_id") or not data.get("leave_type"):
        raise HTTPException(400, "员工ID和假期类型不能为空")
    if not data.get("start_date") or not data.get("end_date"):
        raise HTTPException(400, "开始日期和结束日期不能为空")
    data["id"] = f"LR-{uuid.uuid4().hex[:6]}"
    data["apply_date"] = datetime.now().strftime("%Y-%m-%d"); data["status"] = "已提交"
    data.setdefault("created_at", datetime.now().isoformat())
    try:
        insert("leave_requests", data)
    except Exception as e:
        raise HTTPException(500, f"创建请假申请失败: {str(e)}")
    audit_log(user.get("username", ""), "create", "leave_requests", data["id"], f"员工: {data.get('employee_id','')}, 类型: {data.get('leave_type','')}")
    return {"ok": True}

@app.put("/api/leave-requests/{lid}")
async def update_lr(lid: str, request: Request, user=Depends(get_user)):
    data = await request.json()
    try:
        update("leave_requests", "id", lid, data)
    except Exception as e:
        raise HTTPException(500, f"更新请假申请失败: {str(e)}")
    if data.get("status") == "已批准":
        lr = q("leave_requests", "id=?", (lid,))
        if lr:
            current_year = get_current_year()
            db = database.get_db()
            db.execute("UPDATE leave_balances SET used_days=used_days+?,remaining_days=remaining_days-? WHERE employee_id=? AND year=? AND leave_type=?",
                (lr[0]["days"], lr[0]["days"], lr[0]["employee_id"], current_year, lr[0]["leave_type"]))
            db.commit(); db.close()
    audit_log(user.get("username", ""), "update", "leave_requests", lid, json.dumps(list(data.keys())))
    return {"ok": True}

# ── Expenses ──
@app.get("/api/expenses")
def get_expenses(user=Depends(get_user)): return q("expense_claims")

@app.post("/api/expenses")
async def create_expense(request: Request, user=Depends(get_user)):
    data = await request.json()
    if not data.get("employee_id"):
        raise HTTPException(400, "员工ID不能为空")
    data["id"] = f"EC-{uuid.uuid4().hex[:6]}"
    data["apply_date"] = datetime.now().strftime("%Y-%m-%d"); data["status"] = "已提交"
    data.setdefault("created_at", datetime.now().isoformat())
    try:
        insert("expense_claims", data)
    except Exception as e:
        raise HTTPException(500, f"创建报销申请失败: {str(e)}")
    audit_log(user.get("username", ""), "create", "expense_claims", data["id"], f"员工: {data.get('employee_id','')}, 金额: {data.get('amount','')}")
    return {"ok": True}

@app.put("/api/expenses/{eid}")
async def update_expense(eid: str, request: Request, user=Depends(get_user)):
    data = await request.json()
    try:
        update("expense_claims", "id", eid, data)
    except Exception as e:
        raise HTTPException(500, f"更新报销申请失败: {str(e)}")
    audit_log(user.get("username", ""), "update", "expense_claims", eid, json.dumps(list(data.keys())))
    return {"ok": True}

# ── Other modules ──
@app.get("/api/talent")
def get_talent(user=Depends(get_user)): return q("talent_pool")

@app.get("/api/dispatch")
def get_dispatch(user=Depends(get_user)): return q("dispatch_needs")

@app.get("/api/recruit")
def get_recruit(user=Depends(get_user)): return q("recruit_progress")

@app.get("/api/schedules")
def get_schedules(user=Depends(get_user)):
    role = user.get("role", "worker")
    # Worker/mgr with employee_id: apply grade-based data scope
    if role in ("worker", "mgr") and user.get("employee_id"):
        scope = _check_grade_data_scope(user)
        if scope == "self_only":
            return q("schedules", "employee_id=?", (user["employee_id"],), order="work_date ASC")
        if scope == "own_warehouse":
            wh = _get_employee_warehouse(user)
            if wh:
                return q("schedules", "warehouse_code=?", (wh,), order="work_date ASC")
        if scope == "regional":
            wh = _get_employee_warehouse(user)
            region_whs = _get_region_warehouses(wh) if wh else []
            if region_whs:
                placeholders = ",".join(["?"] * len(region_whs))
                return q("schedules", f"warehouse_code IN ({placeholders})", tuple(region_whs), order="work_date ASC")
    if role == "wh" and user.get("warehouse_code"):
        return q("schedules", "warehouse_code=?", (user["warehouse_code"],), order="work_date ASC")
    return q("schedules", order="work_date ASC")

@app.get("/api/messages")
def get_messages(user=Depends(get_user)): return q("messages", order="timestamp DESC")

@app.get("/api/logs")
def get_logs(user=Depends(get_user)): return q("audit_logs", order="id DESC", limit=200)

# ── Settlement ──
@app.get("/api/settlement")
def get_settlement(mode: str = "own", user=Depends(get_user)):
    role = user.get("role", "worker")
    db = database.get_db()
    # Supplier users only see their own settlement data
    if role == "sup" and user.get("supplier_id"):
        sid = user["supplier_id"]
        rows = db.execute("SELECT supplier_id,warehouse_code,COUNT(DISTINCT employee_id) hc,SUM(hours) h,SUM(hourly_pay) pay FROM timesheet WHERE supplier_id=? GROUP BY warehouse_code", (sid,)).fetchall()
        db.close(); return [dict(r) for r in rows]
    if mode == "own":
        rows = db.execute("SELECT employee_id,employee_name,grade,warehouse_code,SUM(hours) h,SUM(hourly_pay) pay,SUM(ssi_deduct) ssi,SUM(tax_deduct) tax,SUM(net_pay) net FROM timesheet WHERE source='自有' GROUP BY employee_id").fetchall()
    elif mode == "supplier":
        rows = db.execute("SELECT supplier_id,warehouse_code,COUNT(DISTINCT employee_id) hc,SUM(hours) h,SUM(hourly_pay) pay FROM timesheet WHERE source='供应商' GROUP BY supplier_id").fetchall()
    elif mode == "warehouse_income":
        # 对仓库的进账版 - Income report per warehouse (what warehouses owe us)
        rows = db.execute("""SELECT warehouse_code,
            COUNT(DISTINCT employee_id) headcount, SUM(hours) total_hours,
            SUM(hourly_pay + piece_pay + perf_bonus + other_fee) gross_income,
            COUNT(DISTINCT work_date) work_days
            FROM timesheet GROUP BY warehouse_code""").fetchall()
    elif mode == "worker_expense":
        # 对工人的出账版 - Expense report per worker per warehouse (what we pay workers)
        rows = db.execute("""SELECT employee_id, employee_name, warehouse_code, grade,
            SUM(hours) total_hours, SUM(hourly_pay) hourly_total,
            SUM(piece_pay) piece_total, SUM(perf_bonus) perf_total,
            SUM(other_fee) other_total,
            SUM(hourly_pay + piece_pay + perf_bonus + other_fee) gross_pay,
            SUM(ssi_deduct) ssi_total, SUM(tax_deduct) tax_total,
            SUM(net_pay) net_total
            FROM timesheet GROUP BY employee_id, warehouse_code""").fetchall()
    else:
        rows = db.execute("SELECT warehouse_code,COUNT(DISTINCT employee_id) hc,SUM(hours) h,SUM(hourly_pay) cost FROM timesheet GROUP BY warehouse_code").fetchall()
    db.close(); return [dict(r) for r in rows]

# ── Dashboard ──
@app.get("/api/analytics/dashboard")
def dashboard(user=Depends(get_user)):
    db = database.get_db()
    current_year_month = get_current_year_month()
    role = user.get("role", "worker")

    # Supplier-scoped dashboard: only show their workers' data
    if role == "sup" and user.get("supplier_id"):
        sid = user["supplier_id"]
        r = {
            "total_emp": db.execute("SELECT COUNT(*) FROM employees WHERE status='在职' AND supplier_id=?", (sid,)).fetchone()[0],
            "own": 0,
            "supplier": db.execute("SELECT COUNT(*) FROM employees WHERE status='在职' AND supplier_id=?", (sid,)).fetchone()[0],
            "wh_count": db.execute("SELECT COUNT(DISTINCT primary_wh) FROM employees WHERE status='在职' AND supplier_id=?", (sid,)).fetchone()[0],
            "pending_leave": db.execute("SELECT COUNT(*) FROM leave_requests lr JOIN employees e ON lr.employee_id=e.id WHERE lr.status='待审批' AND e.supplier_id=?", (sid,)).fetchone()[0],
            "pending_expense": 0,
            "pending_ts": db.execute("SELECT COUNT(*) FROM timesheet WHERE supplier_id=? AND wh_status='待仓库审批'", (sid,)).fetchone()[0],
            "monthly_hrs": db.execute("SELECT COALESCE(SUM(hours),0) FROM timesheet WHERE supplier_id=? AND work_date LIKE ?", (sid, f"{current_year_month}%")).fetchone()[0],
            "grade_dist": [dict(r) for r in db.execute("SELECT grade,COUNT(*) c FROM employees WHERE status='在职' AND supplier_id=? GROUP BY grade ORDER BY grade", (sid,)).fetchall()],
            "wh_dist": [dict(r) for r in db.execute("SELECT primary_wh w,COUNT(*) c FROM employees WHERE status='在职' AND supplier_id=? GROUP BY primary_wh", (sid,)).fetchall()],
            "service_type_dist": [],
            "dispatch_type_dist": [dict(r) for r in db.execute("SELECT dispatch_type, COUNT(*) c FROM employees WHERE status='在职' AND supplier_id=? AND dispatch_type IS NOT NULL GROUP BY dispatch_type", (sid,)).fetchall()],
        }
        db.close(); return r

    # Warehouse-scoped dashboard
    if role == "wh" and user.get("warehouse_code"):
        wh = user["warehouse_code"]
        r = {
            "total_emp": db.execute("SELECT COUNT(*) FROM employees WHERE status='在职' AND (primary_wh=? OR dispatch_whs LIKE ?)", (wh, f"%{wh}%")).fetchone()[0],
            "own": db.execute("SELECT COUNT(*) FROM employees WHERE source='自有' AND status='在职' AND (primary_wh=? OR dispatch_whs LIKE ?)", (wh, f"%{wh}%")).fetchone()[0],
            "supplier": db.execute("SELECT COUNT(*) FROM employees WHERE source='供应商' AND status='在职' AND (primary_wh=? OR dispatch_whs LIKE ?)", (wh, f"%{wh}%")).fetchone()[0],
            "wh_count": 1,
            "pending_leave": db.execute("SELECT COUNT(*) FROM leave_requests WHERE warehouse_code=? AND status='待审批'", (wh,)).fetchone()[0],
            "pending_expense": 0,
            "pending_ts": db.execute("SELECT COUNT(*) FROM timesheet WHERE warehouse_code=? AND wh_status='待仓库审批'", (wh,)).fetchone()[0],
            "monthly_hrs": db.execute("SELECT COALESCE(SUM(hours),0) FROM timesheet WHERE warehouse_code=? AND work_date LIKE ?", (wh, f"{current_year_month}%")).fetchone()[0],
            "grade_dist": [dict(r) for r in db.execute("SELECT grade,COUNT(*) c FROM employees WHERE status='在职' AND (primary_wh=? OR dispatch_whs LIKE ?) GROUP BY grade ORDER BY grade", (wh, f"%{wh}%")).fetchall()],
            "wh_dist": [{"w": wh, "c": db.execute("SELECT COUNT(*) FROM employees WHERE status='在职' AND (primary_wh=? OR dispatch_whs LIKE ?)", (wh, f"%{wh}%")).fetchone()[0]}],
            "service_type_dist": [],
            "dispatch_type_dist": [dict(r) for r in db.execute("SELECT dispatch_type, COUNT(*) c FROM employees WHERE status='在职' AND (primary_wh=? OR dispatch_whs LIKE ?) AND dispatch_type IS NOT NULL GROUP BY dispatch_type", (wh, f"%{wh}%")).fetchall()],
        }
        db.close(); return r

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
        "service_type_dist": [dict(r) for r in db.execute("SELECT service_type, COUNT(*) c FROM warehouses WHERE service_type IS NOT NULL GROUP BY service_type").fetchall()],
        "dispatch_type_dist": [dict(r) for r in db.execute("SELECT dispatch_type, COUNT(*) c FROM employees WHERE status='在职' AND dispatch_type IS NOT NULL GROUP BY dispatch_type").fetchall()],
    }
    db.close(); return r

# ── Permissions ──
# Role hierarchy: admin (god view) > ceo > mgr > hr > fin > wh > sup > worker
ROLE_HIERARCHY = {
    "admin": 100,  # God view - highest permission level
    "ceo": 90,     # CEO level - 王博 and 袁梁毅
    "mgr": 70,     # Manager
    "hr": 60,      # HR
    "fin": 50,     # Finance
    "wh": 40,      # Warehouse
    "sup": 30,     # Supplier
    "worker": 10,  # Worker
}

# Grade-based permission levels for operational staff (P-series)
# P0-P2: self_only — can only see own data, schedules, and timesheets
# P3: self_only + own warehouse schedules/timesheets (read)
# P4-P6: own_warehouse — timesheet/schedule/dispatch view+edit for own warehouse; salary = suggest only
# P7 (驻仓经理): own_warehouse edit; limited salary/quotation scope for own warehouse
# P8 (区域经理): regional — edit for regional warehouses; limited salary/quotation; browse all others
# P9 (运营总监): all — full edit for all warehouses
# P5+: can submit personnel requests (dispatch_needs) to HR
# P7+: can submit warehouse transfer requests (dispatch_transfers)
GRADE_PERMISSIONS = {
    "P0": {"data_scope": "self_only", "can_dispatch_request": False, "can_transfer_request": False, "salary_scope": "none"},
    "P1": {"data_scope": "self_only", "can_dispatch_request": False, "can_transfer_request": False, "salary_scope": "none"},
    "P2": {"data_scope": "self_only", "can_dispatch_request": False, "can_transfer_request": False, "salary_scope": "none"},
    "P3": {"data_scope": "self_only", "can_dispatch_request": False, "can_transfer_request": False, "salary_scope": "none"},
    "P4": {"data_scope": "own_warehouse", "can_dispatch_request": False, "can_transfer_request": False, "salary_scope": "suggest"},
    "P5": {"data_scope": "own_warehouse", "can_dispatch_request": True, "can_transfer_request": False, "salary_scope": "suggest"},
    "P6": {"data_scope": "own_warehouse", "can_dispatch_request": True, "can_transfer_request": False, "salary_scope": "suggest"},
    "P7": {"data_scope": "own_warehouse", "can_dispatch_request": True, "can_transfer_request": True, "salary_scope": "own_warehouse"},
    "P8": {"data_scope": "regional", "can_dispatch_request": True, "can_transfer_request": True, "salary_scope": "regional"},
    "P9": {"data_scope": "all", "can_dispatch_request": True, "can_transfer_request": True, "salary_scope": "all"},
}

def _get_employee_grade(user: dict) -> str:
    """Get the grade of the employee associated with a user, or '' if not linked."""
    eid = user.get("employee_id")
    if not eid:
        return ""
    db = database.get_db()
    try:
        emp = db.execute("SELECT grade, primary_wh FROM employees WHERE id=?", (eid,)).fetchone()
        return emp["grade"] if emp else ""
    finally:
        db.close()

def _get_grade_permissions(grade: str) -> dict:
    """Get grade-based permission config. Returns default (self_only) for unknown grades."""
    return GRADE_PERMISSIONS.get(grade, {"data_scope": "self_only", "can_dispatch_request": False, "can_transfer_request": False, "salary_scope": "none"})

def _get_employee_warehouse(user: dict) -> str:
    """Get the primary warehouse of the employee associated with a user."""
    eid = user.get("employee_id")
    if not eid:
        return user.get("warehouse_code", "")
    db = database.get_db()
    try:
        emp = db.execute("SELECT primary_wh FROM employees WHERE id=?", (eid,)).fetchone()
        return emp["primary_wh"] if emp else user.get("warehouse_code", "")
    finally:
        db.close()

def _get_region_warehouses(warehouse_code: str) -> list:
    """Get all warehouse codes in the same region as the given warehouse."""
    db = database.get_db()
    try:
        wh = db.execute("SELECT region FROM warehouses WHERE code=?", (warehouse_code,)).fetchone()
        if not wh or not wh["region"]:
            return [warehouse_code]
        region = wh["region"]
        rows = db.execute("SELECT code FROM warehouses WHERE region=?", (region,)).fetchall()
        return [r["code"] for r in rows]
    finally:
        db.close()

def _check_grade_data_scope(user: dict, target_warehouse: str = None) -> str:
    """Determine data access scope based on employee grade.
    Returns: 'all', 'regional', 'own_warehouse', 'self_only'.
    For roles admin/ceo/hr/fin, always returns 'all' (bypasses grade check).
    For mgr role, uses grade-based scope if employee_id is linked."""
    role = user.get("role", "worker")
    if role in ("admin", "ceo", "hr", "fin"):
        return "all"
    grade = _get_employee_grade(user)
    if not grade:
        # No employee linked, fall back to role-based scope
        if role == "wh":
            return "own_warehouse"
        if role == "sup":
            return "own_supplier"
        return "self_only"
    gp = _get_grade_permissions(grade)
    return gp["data_scope"]

def _get_role_level(role: str) -> int:
    """Get numeric role level for hierarchy comparison"""
    return ROLE_HIERARCHY.get(role, 0)

@app.get("/api/permissions")
def get_perms(user=Depends(get_user)): return q("permission_overrides", order="role ASC, module ASC")

@app.get("/api/permissions/check")
def check_permissions(module: str, user=Depends(get_user)):
    """Check current user's permissions for a specific module.
    Admin has god view (all permissions). CEO has near-full access.
    Returns data_scope for fine-grained data access control based on role, grade, department, warehouse."""
    role = user.get("role", "worker")
    # Admin always has full access (god view)
    if role == "admin":
        return {
            "role": "admin", "module": module, "role_level": 100,
            "can_view": 1, "can_create": 1, "can_edit": 1, "can_delete": 1,
            "can_export": 1, "can_approve": 1, "can_import": 1,
            "hidden_fields": "", "editable_fields": "",
            "data_scope": "all", "scope_grades": "", "scope_departments": "", "scope_warehouses": ""
        }
    db = database.get_db()
    perm = db.execute("SELECT * FROM permission_overrides WHERE role=? AND module=?", (role, module)).fetchone()
    db.close()
    if not perm:
        return {"role": role, "module": module, "role_level": _get_role_level(role),
                "can_view": 0, "can_create": 0, "can_edit": 0, "can_delete": 0,
                "can_export": 0, "can_approve": 0, "can_import": 0,
                "hidden_fields": "", "editable_fields": "",
                "data_scope": "self_only", "scope_grades": "", "scope_departments": "", "scope_warehouses": ""}
    result = dict(perm)
    result["role_level"] = _get_role_level(role)
    return result

@app.get("/api/permissions/my")
def get_my_permissions(user=Depends(get_user)):
    """Get all permissions for the current user's role, including data scope and user context"""
    role = user.get("role", "worker")
    role_level = _get_role_level(role)
    user_context = {
        "supplier_id": user.get("supplier_id"),
        "warehouse_code": user.get("warehouse_code"),
    }
    if role == "admin":
        # Admin: god view, return all modules with full access
        db = database.get_db()
        modules = db.execute("SELECT DISTINCT module FROM permission_overrides").fetchall()
        db.close()
        return {
            "role": "admin", "role_level": 100, "is_admin": True, "is_ceo": False,
            "user_context": user_context,
            "permissions": {m["module"]: {
                "can_view": 1, "can_create": 1, "can_edit": 1, "can_delete": 1,
                "can_export": 1, "can_approve": 1, "can_import": 1,
                "hidden_fields": "", "editable_fields": "",
                "data_scope": "all", "scope_grades": "", "scope_departments": "", "scope_warehouses": ""
            } for m in modules}
        }
    db = database.get_db()
    perms = db.execute("SELECT * FROM permission_overrides WHERE role=?", (role,)).fetchall()
    db.close()
    return {
        "role": role, "role_level": role_level,
        "is_admin": role == "admin", "is_ceo": role == "ceo",
        "user_context": user_context,
        "permissions": {p["module"]: dict(p) for p in perms}
    }

@app.get("/api/permissions/grade")
def get_grade_permissions(user=Depends(get_user)):
    """Get grade-based permissions for the current user's employee grade.
    Returns grade data scope, dispatch request ability, transfer request ability, and salary scope."""
    role = user.get("role", "worker")
    if role in ("admin", "ceo"):
        return {
            "grade": "", "data_scope": "all",
            "can_dispatch_request": True, "can_transfer_request": True,
            "salary_scope": "all", "warehouse": "", "region_warehouses": []
        }
    grade = _get_employee_grade(user)
    gp = _get_grade_permissions(grade)
    wh = _get_employee_warehouse(user)
    region_whs = _get_region_warehouses(wh) if wh and gp["data_scope"] == "regional" else []
    return {
        "grade": grade,
        "data_scope": gp["data_scope"],
        "can_dispatch_request": gp["can_dispatch_request"],
        "can_transfer_request": gp["can_transfer_request"],
        "salary_scope": gp["salary_scope"],
        "warehouse": wh,
        "region_warehouses": region_whs
    }

@app.get("/api/regions")
def get_regions(user=Depends(get_user)):
    """Get all warehouse regions with their warehouses."""
    db = database.get_db()
    rows = db.execute("SELECT code, name, region FROM warehouses WHERE region IS NOT NULL AND region != '' ORDER BY region, code").fetchall()
    db.close()
    regions = {}
    for r in rows:
        region = r["region"]
        if region not in regions:
            regions[region] = {"name": region, "warehouses": []}
        regions[region]["warehouses"].append({"code": r["code"], "name": r["name"]})
    return list(regions.values())

@app.post("/api/permissions/update")
async def update_perm(request: Request, user=Depends(get_user)):
    d = await request.json()
    if not d.get("role") or not d.get("module"):
        raise HTTPException(400, "角色和模块不能为空")
    # Only admin can update permissions
    if user.get("role") != "admin":
        raise HTTPException(403, "仅管理员可修改权限设置")
    db = database.get_db()
    db.execute("""UPDATE permission_overrides SET can_view=?,can_create=?,can_edit=?,can_delete=?,
        can_export=?,can_approve=?,can_import=?,hidden_fields=?,editable_fields=?,
        data_scope=?,scope_grades=?,scope_departments=?,scope_warehouses=? WHERE role=? AND module=?""",
        (d.get("can_view",0),d.get("can_create",0),d.get("can_edit",0),d.get("can_delete",0),
         d.get("can_export",0),d.get("can_approve",0),d.get("can_import",0),
         d.get("hidden_fields",""),d.get("editable_fields",""),
         d.get("data_scope","all"),d.get("scope_grades",""),d.get("scope_departments",""),d.get("scope_warehouses",""),
         d["role"],d["module"]))
    db.commit(); db.close()
    audit_log(user.get("username", ""), "update", "permission_overrides", f"{d['role']}/{d['module']}", json.dumps(d))
    return {"ok": True}

@app.get("/api/roles")
def get_roles(user=Depends(get_user)):
    """Get all available roles with hierarchy levels"""
    return [
        {"role": "admin", "label": "系统管理员", "level": 100, "description": "上帝视角 - 最高权限"},
        {"role": "ceo", "label": "CEO", "level": 90, "description": "公司最高管理层 (王博/袁梁毅)"},
        {"role": "mgr", "label": "经理", "level": 70, "description": "部门/区域经理"},
        {"role": "hr", "label": "人事", "level": 60, "description": "人力资源管理"},
        {"role": "fin", "label": "财务", "level": 50, "description": "财务管理"},
        {"role": "wh", "label": "仓库", "level": 40, "description": "仓库管理"},
        {"role": "sup", "label": "供应商", "level": 30, "description": "供应商账号"},
        {"role": "worker", "label": "员工", "level": 10, "description": "一线工人"},
    ]

# Module field definitions with Chinese labels and sensitivity markers
MODULE_FIELD_DEFINITIONS = {
    "employees": {
        "id": {"label": "工号", "sensitive": False},
        "name": {"label": "姓名", "sensitive": False},
        "phone": {"label": "电话", "sensitive": True},
        "email": {"label": "邮箱", "sensitive": True},
        "nationality": {"label": "国籍", "sensitive": False},
        "gender": {"label": "性别", "sensitive": False},
        "birth_date": {"label": "出生日期", "sensitive": True},
        "id_type": {"label": "证件类型", "sensitive": True},
        "id_number": {"label": "证件号码", "sensitive": True},
        "address": {"label": "地址", "sensitive": True},
        "source": {"label": "来源", "sensitive": False},
        "supplier_id": {"label": "供应商ID", "sensitive": False},
        "biz_line": {"label": "业务线", "sensitive": False},
        "department": {"label": "部门", "sensitive": False},
        "primary_wh": {"label": "主仓库", "sensitive": False},
        "dispatch_whs": {"label": "派遣仓库", "sensitive": False},
        "position": {"label": "岗位", "sensitive": False},
        "grade": {"label": "职级", "sensitive": False},
        "wage_level": {"label": "薪级", "sensitive": True},
        "settle_method": {"label": "结算方式", "sensitive": False},
        "base_salary": {"label": "基本工资", "sensitive": True},
        "hourly_rate": {"label": "时薪", "sensitive": True},
        "perf_bonus": {"label": "绩效奖金", "sensitive": True},
        "extra_bonus": {"label": "额外奖金", "sensitive": True},
        "tax_mode": {"label": "税务方式", "sensitive": True},
        "tax_no": {"label": "税号", "sensitive": True},
        "tax_id": {"label": "税务ID", "sensitive": True},
        "tax_class": {"label": "税务等级", "sensitive": True},
        "ssn": {"label": "社保号", "sensitive": True},
        "iban": {"label": "银行账户(IBAN)", "sensitive": True},
        "health_insurance": {"label": "医疗保险", "sensitive": True},
        "languages": {"label": "语言", "sensitive": False},
        "special_skills": {"label": "特殊技能", "sensitive": False},
        "contract_type": {"label": "合同类型", "sensitive": False},
        "dispatch_type": {"label": "派遣类型", "sensitive": False},
        "contract_start": {"label": "合同开始", "sensitive": False},
        "contract_end": {"label": "合同结束", "sensitive": False},
        "emergency_contact": {"label": "紧急联系人", "sensitive": True},
        "emergency_phone": {"label": "紧急联系电话", "sensitive": True},
        "work_permit_no": {"label": "工作许可号", "sensitive": True},
        "work_permit_expiry": {"label": "工作许可到期", "sensitive": True},
        "status": {"label": "状态", "sensitive": False},
        "join_date": {"label": "入职日期", "sensitive": False},
        "leave_date": {"label": "离职日期", "sensitive": False},
    },
    "suppliers": {
        "id": {"label": "供应商ID", "sensitive": False},
        "name": {"label": "名称", "sensitive": False},
        "bank_name": {"label": "银行名称", "sensitive": True},
        "bank_account": {"label": "银行账号", "sensitive": True},
        "tax_handle": {"label": "税务处理", "sensitive": True},
        "contact_name": {"label": "联系人", "sensitive": False},
        "contact_phone": {"label": "联系电话", "sensitive": False},
        "contact_email": {"label": "联系邮箱", "sensitive": False},
    },
}

@app.get("/api/field-definitions/{module}")
def get_field_definitions(module: str, user=Depends(get_user)):
    """Get field definitions for a module, including labels and sensitivity markers.
    Admin only endpoint for configuring field-level visibility."""
    if user.get("role") != "admin":
        raise HTTPException(403, "仅管理员可查看字段定义")
    fields = MODULE_FIELD_DEFINITIONS.get(module, {})
    return {"module": module, "fields": fields}

# ── Batch Import / Export ──

def _check_permission(user, module: str, action: str):
    """Check user permission for a specific action. Admin always passes."""
    role = user.get("role", "worker")
    if role == "admin":
        return True
    db = database.get_db()
    perm = db.execute("SELECT * FROM permission_overrides WHERE role=? AND module=?", (role, module)).fetchone()
    db.close()
    if not perm:
        return False
    perm_dict = dict(perm)
    return bool(perm_dict.get(action, 0))

def _get_hidden_fields(role: str, module: str) -> list:
    """Get list of hidden fields for a role/module pair. Admin sees all fields."""
    if role == "admin":
        return []
    db = database.get_db()
    try:
        perm = db.execute("SELECT hidden_fields FROM permission_overrides WHERE role=? AND module=?",
                          (role, module)).fetchone()
        if perm and perm["hidden_fields"]:
            return [f.strip() for f in perm["hidden_fields"].split(",") if f.strip()]
        return []
    finally:
        db.close()

def _get_editable_fields(role: str, module: str) -> list:
    """Get list of editable fields for a role/module pair. Empty means all editable (when permission allows)."""
    if role == "admin":
        return []  # empty = all editable for admin
    db = database.get_db()
    try:
        perm = db.execute("SELECT editable_fields FROM permission_overrides WHERE role=? AND module=?",
                          (role, module)).fetchone()
        if perm and perm["editable_fields"]:
            return [f.strip() for f in perm["editable_fields"].split(",") if f.strip()]
        return []  # empty = all editable (based on can_edit permission)
    finally:
        db.close()

def _filter_hidden_fields(rows: list, role: str, module: str) -> list:
    """Filter out hidden fields from a list of row dicts based on role permissions.
    Admin sees all fields. Returns rows with hidden fields removed."""
    hidden = _get_hidden_fields(role, module)
    if not hidden:
        return rows
    return [{k: v for k, v in row.items() if k not in hidden} for row in rows]

def _enforce_editable_fields(data: dict, role: str, module: str) -> dict:
    """Remove fields that the role is not allowed to edit.
    If editable_fields is set, only those fields can be edited.
    Admin can edit all fields. System fields (updated_at) are always allowed.
    Returns filtered data dict."""
    if role == "admin":
        return data
    editable = _get_editable_fields(role, module)
    if not editable:
        return data  # empty = all editable (based on can_edit permission)
    # Always allow system-managed timestamp fields
    system_fields = {"updated_at", "created_at"}
    return {k: v for k, v in data.items() if k in editable or k in system_fields}

# Field definitions for each exportable table (column order for import/export)
TABLE_EXPORT_FIELDS = {
    "employees": ["id","name","phone","email","nationality","gender","birth_date","id_type","id_number",
                   "address","source","supplier_id","biz_line","department","primary_wh","dispatch_whs",
                   "position","grade","wage_level","settle_method","base_salary","hourly_rate",
                   "contract_type","dispatch_type","contract_start","contract_end",
                   "emergency_contact","emergency_phone","work_permit_no","work_permit_expiry",
                   "status","join_date","leave_date"],
    "suppliers": ["id","name","type","biz_line","contract_no","contract_start","contract_end",
                   "settle_cycle","currency","contact_name","contact_phone","contact_email","address",
                   "tax_handle","service_scope","dispatch_types","bank_name","bank_account",
                   "max_headcount","current_headcount","status","rating","notes"],
    "timesheet": ["id","employee_id","employee_name","source","supplier_id","biz_line",
                   "work_date","warehouse_code","start_time","end_time","hours","position","grade",
                   "settle_method","base_rate","hourly_pay","piece_pay","perf_bonus","other_fee",
                   "ssi_deduct","tax_deduct","net_pay","container_no","container_type",
                   "wh_status","notes"],
    "warehouses": ["code","name","address","manager","phone","client_name","project_no",
                    "biz_line","client_settle","service_type","cooperation_mode",
                    "contract_start_date","contract_end_date","headcount_quota","current_headcount",
                    "tax_number","contact_person","contact_email"],
    "leave_requests": ["id","employee_id","employee_name","grade","warehouse_code",
                        "leave_type","start_date","end_date","days","reason","status"],
    "expense_claims": ["id","employee_id","employee_name","grade","department",
                        "claim_type","amount","currency","claim_date","description","status"],
    "performance_reviews": ["id","employee_id","employee_name","grade","review_period",
                             "review_type","total_score","rating","reviewer","status"],
    "container_records": ["id","container_no","work_date","warehouse_code","container_type",
                           "load_type","dock_no","ratio","team_no","team_size","member_ids",
                           "start_time","end_time","duration_minutes",
                           "client_revenue","team_pay","split_method","wh_status","notes"],
    "schedules": ["id","employee_id","employee_name","warehouse_code","work_date",
                   "shift","start_time","end_time","position","biz_line","status","notes"],
    "dispatch_needs": ["id","biz_line","warehouse_code","position","headcount",
                        "start_date","end_date","shift","client_settle","client_rate",
                        "matched_count","status","priority","requester","notes"],
}

MODULE_MAP = {"employees": "employees", "suppliers": "suppliers", "timesheet": "timesheet",
              "warehouses": "warehouse", "leave_requests": "leave", "expense_claims": "expense",
              "performance_reviews": "performance", "container_records": "container",
              "schedules": "schedule", "dispatch_needs": "dispatch"}

# Chinese labels for export template headers
TABLE_FIELD_LABELS = {
    "employees": {"id":"工号","name":"姓名","phone":"电话","email":"邮箱","nationality":"国籍","gender":"性别",
                   "birth_date":"出生日期","id_type":"证件类型","id_number":"证件号码","address":"地址",
                   "source":"来源","supplier_id":"供应商ID","biz_line":"业务线","department":"部门",
                   "primary_wh":"主仓库","dispatch_whs":"派遣仓库","position":"岗位","grade":"职级",
                   "wage_level":"薪级","settle_method":"结算方式","base_salary":"基本工资","hourly_rate":"时薪",
                   "contract_type":"合同类型","dispatch_type":"派遣类型","contract_start":"合同开始",
                   "contract_end":"合同结束","emergency_contact":"紧急联系人","emergency_phone":"紧急联系电话",
                   "work_permit_no":"工作许可号","work_permit_expiry":"工作许可到期","status":"状态",
                   "join_date":"入职日期","leave_date":"离职日期"},
    "suppliers": {"id":"供应商ID","name":"名称","type":"类型","biz_line":"业务线","contract_no":"合同编号",
                   "contract_start":"合同开始","contract_end":"合同结束","settle_cycle":"结算周期",
                   "currency":"币种","contact_name":"联系人","contact_phone":"联系电话","contact_email":"邮箱",
                   "address":"地址","tax_handle":"税务处理","service_scope":"服务范围","dispatch_types":"派遣类型",
                   "bank_name":"银行","bank_account":"银行账号","max_headcount":"最大人数",
                   "current_headcount":"当前人数","status":"状态","rating":"评级","notes":"备注"},
    "timesheet": {"id":"编号","employee_id":"工号","employee_name":"姓名","source":"来源","supplier_id":"供应商",
                   "biz_line":"业务线","work_date":"工作日期","warehouse_code":"仓库","start_time":"开始时间",
                   "end_time":"结束时间","hours":"工时","position":"岗位","grade":"职级","settle_method":"结算方式",
                   "base_rate":"基础费率","hourly_pay":"时薪","piece_pay":"计件","perf_bonus":"绩效奖金",
                   "other_fee":"其他费用","ssi_deduct":"社保扣除","tax_deduct":"税扣除","net_pay":"实发",
                   "container_no":"柜号","container_type":"柜型","wh_status":"状态","notes":"备注"},
    "warehouses": {"code":"仓库编码","name":"仓库名称","address":"地址","manager":"经理","phone":"电话",
                    "client_name":"客户","project_no":"项目编号","biz_line":"业务线","client_settle":"客户结算",
                    "service_type":"服务类型","cooperation_mode":"合作模式","contract_start_date":"合同开始",
                    "contract_end_date":"合同结束","headcount_quota":"合同人数","current_headcount":"当前人数",
                    "tax_number":"税号","contact_person":"联系人","contact_email":"联系邮箱"},
    "leave_requests": {"id":"编号","employee_id":"工号","employee_name":"姓名","grade":"职级",
                        "warehouse_code":"仓库","leave_type":"假期类型","start_date":"开始日期",
                        "end_date":"结束日期","days":"天数","reason":"原因","status":"状态"},
    "expense_claims": {"id":"编号","employee_id":"工号","employee_name":"姓名","grade":"职级",
                        "department":"部门","claim_type":"报销类型","amount":"金额","currency":"币种",
                        "claim_date":"报销日期","description":"描述","status":"状态"},
    "performance_reviews": {"id":"编号","employee_id":"工号","employee_name":"姓名","grade":"职级",
                             "review_period":"考核周期","review_type":"考核类型","total_score":"总分",
                             "rating":"评级","reviewer":"评审人","status":"状态"},
    "container_records": {"id":"编号","container_no":"柜号","work_date":"工作日期","warehouse_code":"仓库",
                           "container_type":"柜型","load_type":"装卸类型","dock_no":"垛口","ratio":"比例",
                           "team_no":"组号","team_size":"人数","member_ids":"成员ID",
                           "start_time":"开始时间","end_time":"结束时间","duration_minutes":"时长(分钟)",
                           "client_revenue":"客户收入","team_pay":"团队费用","split_method":"分配方式",
                           "wh_status":"状态","notes":"备注"},
    "schedules": {"id":"编号","employee_id":"工号","employee_name":"姓名","warehouse_code":"仓库",
                   "work_date":"工作日期","shift":"班次","start_time":"开始时间","end_time":"结束时间",
                   "position":"岗位","biz_line":"业务线","status":"状态","notes":"备注"},
    "dispatch_needs": {"id":"编号","biz_line":"业务线","warehouse_code":"仓库","position":"岗位",
                        "headcount":"需求人数","start_date":"开始日期","end_date":"结束日期","shift":"班次",
                        "client_settle":"客户结算","client_rate":"客户费率","matched_count":"已匹配",
                        "status":"状态","priority":"优先级","requester":"申请人","notes":"备注"},
}

@app.get("/api/template/{table}")
def get_template(table: str, user=Depends(get_user)):
    """Get import template with field names and Chinese labels for a table."""
    if table not in TABLE_EXPORT_FIELDS:
        raise HTTPException(400, f"不支持的表: {table}")
    fields = TABLE_EXPORT_FIELDS[table]
    labels = TABLE_FIELD_LABELS.get(table, {})
    header = [labels.get(f, f) for f in fields]
    sample = {f: "" for f in fields}
    return {"table": table, "fields": fields, "labels": header, "sample": sample}

@app.get("/api/export/{table}")
def export_table(table: str, fmt: str = "json", user=Depends(get_user)):
    """Export table data. Supports format: json, csv, excel, pdf. Respects role-based field visibility."""
    if table not in TABLE_EXPORT_FIELDS:
        raise HTTPException(400, f"不支持导出的表: {table}")
    module = MODULE_MAP.get(table, table)
    if not _check_permission(user, module, "can_export"):
        raise HTTPException(403, "无导出权限")
    fields = TABLE_EXPORT_FIELDS[table]
    labels = TABLE_FIELD_LABELS.get(table, {})
    role = user.get("role", "worker")
    # Apply hidden_fields filter (admin sees all)
    if role != "admin":
        db = database.get_db()
        perm = db.execute("SELECT hidden_fields FROM permission_overrides WHERE role=? AND module=?",
                          (role, module)).fetchone()
        db.close()
        if perm and perm["hidden_fields"]:
            hidden = [f.strip() for f in perm["hidden_fields"].split(",") if f.strip()]
            fields = [f for f in fields if f not in hidden]
    # Query data
    rows = q(table)
    export_data = []
    for row in rows:
        export_data.append({f: row.get(f) for f in fields if f in row})

    if fmt == "csv":
        import io, csv
        output = io.StringIO()
        writer = csv.writer(output)
        header = [labels.get(f, f) for f in fields]
        writer.writerow(header)
        for row in export_data:
            writer.writerow([row.get(f, "") for f in fields])
        csv_bytes = output.getvalue().encode("utf-8-sig")
        from fastapi.responses import Response
        return Response(content=csv_bytes, media_type="text/csv",
                        headers={"Content-Disposition": f'attachment; filename="{table}.csv"'})

    if fmt == "excel":
        import io, csv
        # Generate CSV with BOM as Excel-compatible format
        output = io.StringIO()
        writer = csv.writer(output, dialect="excel")
        header = [labels.get(f, f) for f in fields]
        writer.writerow(header)
        for row in export_data:
            writer.writerow([row.get(f, "") for f in fields])
        csv_bytes = output.getvalue().encode("utf-8-sig")
        from fastapi.responses import Response
        return Response(content=csv_bytes,
                        media_type="application/vnd.ms-excel",
                        headers={"Content-Disposition": f'attachment; filename="{table}.xls"'})

    if fmt == "pdf":
        # Generate a tab-separated text report
        import io
        lines = []
        header = [labels.get(f, f) for f in fields]
        lines.append("\t".join(header))
        lines.append("-" * 80)
        for row in export_data:
            lines.append("\t".join([str(row.get(f, "")) for f in fields]))
        content = "\n".join(lines)
        from fastapi.responses import Response
        return Response(content=content.encode("utf-8"),
                        media_type="text/plain",
                        headers={"Content-Disposition": f'attachment; filename="{table}_report.txt"'})

    return {"table": table, "fields": fields, "count": len(export_data), "data": export_data}

@app.post("/api/import/{table}")
async def import_table(table: str, request: Request, user=Depends(get_user)):
    """Batch import records into a table from JSON array.
    Request body: {"data": [{...}, {...}, ...]}"""
    if table not in TABLE_EXPORT_FIELDS:
        raise HTTPException(400, f"不支持导入的表: {table}")
    module = MODULE_MAP.get(table, table)
    if not _check_permission(user, module, "can_import"):
        raise HTTPException(403, "无导入权限")

    body = await request.json()
    records = body.get("data", [])
    if not records or not isinstance(records, list):
        raise HTTPException(400, "导入数据不能为空，需要 {\"data\": [...]}")

    id_col = "code" if table == "warehouses" else "id"
    success = 0
    errors = []
    db = database.get_db()
    try:
        for i, record in enumerate(records):
            try:
                # Auto-generate ID if missing
                if id_col not in record or not record[id_col]:
                    if table == "employees":
                        record["id"] = f"YB-{uuid.uuid4().hex[:6].upper()}"
                    elif table == "suppliers":
                        record["id"] = f"SUP-{uuid.uuid4().hex[:4].upper()}"
                    elif table == "timesheet":
                        record["id"] = f"WT-{uuid.uuid4().hex[:8]}"
                    elif table == "leave_requests":
                        record["id"] = f"LR-{uuid.uuid4().hex[:6]}"
                    elif table == "expense_claims":
                        record["id"] = f"EC-{uuid.uuid4().hex[:6]}"
                    elif table == "performance_reviews":
                        record["id"] = f"PR-{uuid.uuid4().hex[:6]}"
                    elif table == "container_records":
                        record["id"] = f"CT-{uuid.uuid4().hex[:6]}"
                    elif table == "schedules":
                        record["id"] = f"SC-{uuid.uuid4().hex[:6]}"
                    elif table == "dispatch_needs":
                        record["id"] = f"DN-{uuid.uuid4().hex[:6]}"
                now = datetime.now().isoformat()
                record.setdefault("created_at", now)
                # Only set updated_at for tables that have this column
                _tables_with_updated_at = {"employees", "suppliers", "timesheet", "warehouses",
                                           "leave_requests", "expense_claims", "performance_reviews"}
                if table in _tables_with_updated_at:
                    record.setdefault("updated_at", now)

                # Validate required fields
                if table == "employees" and not record.get("name"):
                    errors.append({"row": i, "error": "员工姓名不能为空"})
                    continue
                if table == "suppliers" and not record.get("name"):
                    errors.append({"row": i, "error": "供应商名称不能为空"})
                    continue

                # Check for existing record (upsert logic)
                existing = db.execute(f"SELECT {id_col} FROM {table} WHERE {id_col}=?",
                                      (record[id_col],)).fetchone()
                if existing:
                    # Update existing
                    update_data = {k: v for k, v in record.items() if k != id_col}
                    if table in _tables_with_updated_at:
                        update_data["updated_at"] = now
                    sets = ",".join(f"{k}=?" for k in update_data.keys())
                    db.execute(f"UPDATE {table} SET {sets} WHERE {id_col}=?",
                               list(update_data.values()) + [record[id_col]])
                else:
                    # Insert new
                    cols = ",".join(record.keys())
                    phs = ",".join(["?"] * len(record))
                    db.execute(f"INSERT INTO {table}({cols}) VALUES({phs})", list(record.values()))
                success += 1
            except Exception as e:
                errors.append({"row": i, "error": str(e)})
        db.commit()
    except Exception as e:
        db.rollback()
        raise HTTPException(500, f"导入失败: {str(e)}")
    finally:
        db.close()
    audit_log(user.get("username", ""), "import", table, f"batch_{success}",
              f"导入{success}条, 失败{len(errors)}条")
    return {"ok": True, "success": success, "errors": errors, "total": len(records)}

# ── Update/Delete endpoints for remaining tables ──

@app.put("/api/timesheet/{tid}")
async def update_timesheet(tid: str, request: Request, user=Depends(get_user)):
    data = await request.json()
    data["updated_at"] = datetime.now().isoformat()
    try:
        update("timesheet", "id", tid, data)
    except Exception as e:
        raise HTTPException(500, f"更新工时记录失败: {str(e)}")
    audit_log(user.get("username", ""), "update", "timesheet", tid, json.dumps(list(data.keys())))
    return {"ok": True}

@app.post("/api/talent")
async def create_talent(request: Request, user=Depends(get_user)):
    data = await request.json()
    if not data.get("name"):
        raise HTTPException(400, "人才姓名不能为空")
    data["id"] = f"TP-{uuid.uuid4().hex[:6]}"
    data.setdefault("created_at", datetime.now().isoformat())
    try:
        insert("talent_pool", data)
    except Exception as e:
        raise HTTPException(500, f"创建人才记录失败: {str(e)}")
    audit_log(user.get("username", ""), "create", "talent_pool", data["id"], f"人才: {data.get('name','')}")
    return {"ok": True, "id": data["id"]}

@app.put("/api/talent/{tid}")
async def update_talent(tid: str, request: Request, user=Depends(get_user)):
    data = await request.json()
    try:
        update("talent_pool", "id", tid, data)
    except Exception as e:
        raise HTTPException(500, f"更新人才记录失败: {str(e)}")
    audit_log(user.get("username", ""), "update", "talent_pool", tid, json.dumps(list(data.keys())))
    return {"ok": True}

@app.post("/api/dispatch")
async def create_dispatch(request: Request, user=Depends(get_user)):
    data = await request.json()
    if not data.get("warehouse_code"):
        raise HTTPException(400, "仓库编码不能为空")
    # Grade-based check: P5+ can submit personnel requests, or admin/ceo/hr/mgr roles
    role = user.get("role", "worker")
    if role not in ("admin", "ceo", "hr", "mgr"):
        grade = _get_employee_grade(user)
        gp = _get_grade_permissions(grade)
        if not gp["can_dispatch_request"]:
            raise HTTPException(403, "P5及以上职级方可直接发起人员需求 / Only P5+ can submit personnel requests")
    data["id"] = f"DN-{uuid.uuid4().hex[:6]}"
    data.setdefault("created_at", datetime.now().isoformat())
    data.setdefault("requester", user.get("username", ""))
    try:
        insert("dispatch_needs", data)
    except Exception as e:
        raise HTTPException(500, f"创建派遣需求失败: {str(e)}")
    audit_log(user.get("username", ""), "create", "dispatch_needs", data["id"], f"仓库: {data.get('warehouse_code','')}")
    return {"ok": True, "id": data["id"]}

@app.put("/api/dispatch/{did}")
async def update_dispatch(did: str, request: Request, user=Depends(get_user)):
    data = await request.json()
    try:
        update("dispatch_needs", "id", did, data)
    except Exception as e:
        raise HTTPException(500, f"更新派遣需求失败: {str(e)}")
    audit_log(user.get("username", ""), "update", "dispatch_needs", did, json.dumps(list(data.keys())))
    return {"ok": True}

@app.post("/api/schedules")
async def create_schedule(request: Request, user=Depends(get_user)):
    data = await request.json()
    if not data.get("employee_id") or not data.get("work_date"):
        raise HTTPException(400, "员工ID和工作日期不能为空")
    data["id"] = f"SC-{uuid.uuid4().hex[:6]}"
    data.setdefault("created_at", datetime.now().isoformat())
    try:
        insert("schedules", data)
    except Exception as e:
        raise HTTPException(500, f"创建排班记录失败: {str(e)}")
    audit_log(user.get("username", ""), "create", "schedules", data["id"], f"员工: {data.get('employee_id','')}")
    return {"ok": True, "id": data["id"]}

@app.put("/api/schedules/{sid}")
async def update_schedule(sid: str, request: Request, user=Depends(get_user)):
    data = await request.json()
    try:
        update("schedules", "id", sid, data)
    except Exception as e:
        raise HTTPException(500, f"更新排班记录失败: {str(e)}")
    audit_log(user.get("username", ""), "update", "schedules", sid, json.dumps(list(data.keys())))
    return {"ok": True}

# ── Dispatch Transfers (人员调仓) ──
@app.get("/api/dispatch-transfers")
def get_dispatch_transfers(user=Depends(get_user)):
    """获取人员调仓记录列表"""
    role = user.get("role", "worker")
    if role in ("admin", "ceo", "hr"):
        return q("dispatch_transfers", order="created_at DESC")
    # Grade-based scoping
    if user.get("employee_id"):
        scope = _check_grade_data_scope(user)
        if scope == "all":
            return q("dispatch_transfers", order="created_at DESC")
        if scope == "regional":
            wh = _get_employee_warehouse(user)
            region_whs = _get_region_warehouses(wh) if wh else []
            if region_whs:
                placeholders = ",".join(["?"] * len(region_whs))
                return q("dispatch_transfers", f"from_wh IN ({placeholders}) OR to_wh IN ({placeholders})",
                         tuple(region_whs) + tuple(region_whs), order="created_at DESC")
        if scope == "own_warehouse":
            wh = _get_employee_warehouse(user)
            if wh:
                return q("dispatch_transfers", "from_wh=? OR to_wh=?", (wh, wh), order="created_at DESC")
    return q("dispatch_transfers", "employee_id=?", (user.get("employee_id", ""),), order="created_at DESC")

@app.post("/api/dispatch-transfers")
async def create_dispatch_transfer(request: Request, user=Depends(get_user)):
    """创建人员调仓申请 - P7及以上或admin/ceo/hr可发起"""
    role = user.get("role", "worker")
    # Grade-based check: P7+ can submit transfer requests, or admin/ceo/hr
    if role not in ("admin", "ceo", "hr"):
        grade = _get_employee_grade(user)
        gp = _get_grade_permissions(grade)
        if not gp["can_transfer_request"]:
            raise HTTPException(403, "P7及以上职级方可发起人员调仓申请 / Only P7+ can submit transfer requests")
    data = await request.json()
    if not data.get("employee_id"):
        raise HTTPException(400, "员工ID不能为空")
    if not data.get("from_wh") or not data.get("to_wh"):
        raise HTTPException(400, "调出仓库和调入仓库不能为空")
    data["id"] = f"DT-{uuid.uuid4().hex[:6]}"
    data.setdefault("transfer_type", "临时支援")
    data.setdefault("status", "待审批")
    data.setdefault("created_at", datetime.now().isoformat())
    try:
        insert("dispatch_transfers", data)
    except Exception as e:
        raise HTTPException(500, f"创建调仓申请失败: {str(e)}")
    audit_log(user.get("username", ""), "create", "dispatch_transfers", data["id"],
              f"调仓: {data.get('employee_id','')} 从{data.get('from_wh','')}到{data.get('to_wh','')}, 类型: {data.get('transfer_type','')}")
    return {"ok": True, "id": data["id"]}

@app.put("/api/dispatch-transfers/{tid}")
async def update_dispatch_transfer(tid: str, request: Request, user=Depends(get_user)):
    """更新人员调仓申请（审批、状态变更等）"""
    data = await request.json()
    try:
        update("dispatch_transfers", "id", tid, data)
    except Exception as e:
        raise HTTPException(500, f"更新调仓申请失败: {str(e)}")
    audit_log(user.get("username", ""), "update", "dispatch_transfers", tid, json.dumps(data, ensure_ascii=False))
    return {"ok": True}

@app.delete("/api/{table}/{record_id}")
async def delete_record(table: str, record_id: str, user=Depends(get_user)):
    """Soft delete for admin/ceo only. Sets status to '已删除' or removes record."""
    if user.get("role") not in ["admin", "ceo"]:
        raise HTTPException(403, "仅管理员或CEO可执行删除操作")
    allowed_delete_tables = {"employees", "suppliers", "talent_pool", "dispatch_needs",
                              "schedules", "leave_requests", "expense_claims"}
    if table not in allowed_delete_tables:
        raise HTTPException(400, f"不支持删除的表: {table}")
    _validate_table_name(table)
    db = database.get_db()
    try:
        id_col = "code" if table == "warehouses" else "id"
        # Try soft-delete first (set status)
        row = db.execute(f"SELECT * FROM {table} WHERE {id_col}=?", (record_id,)).fetchone()
        if not row:
            raise HTTPException(404, "记录不存在")
        if "status" in dict(row):
            db.execute(f"UPDATE {table} SET status='已删除' WHERE {id_col}=?", (record_id,))
        else:
            db.execute(f"DELETE FROM {table} WHERE {id_col}=?", (record_id,))
        db.commit()
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(500, f"删除失败: {str(e)}")
    finally:
        db.close()
    audit_log(user.get("username", ""), "delete", table, record_id, f"由{user.get('display_name', user.get('username',''))}删除")
    return {"ok": True}

# ── File Upload ──
@app.post("/api/upload")
async def upload_file(file: UploadFile = File(...), category: str = Form("general")):
    ext = os.path.splitext(file.filename)[1]
    fname = f"{category}_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}{ext}"
    path = os.path.join(UPLOAD_DIR, fname)
    content = await file.read()
    with open(path, "wb") as f: f.write(content)
    return {"filename": fname, "url": f"/uploads/{fname}", "size": len(content)}

# ── Payslips - 工资条 ──
@app.get("/api/payslips")
def get_payslips(month: Optional[str] = None, employee_id: Optional[str] = None, user=Depends(get_user)):
    """获取工资条列表"""
    db = database.get_db()
    sql = "SELECT * FROM payslips WHERE 1=1"
    params: list = []
    if month:
        sql += " AND month=?"
        params.append(month)
    if employee_id:
        sql += " AND employee_id=?"
        params.append(employee_id)
    sql += " ORDER BY month DESC, employee_name ASC"
    rows = db.execute(sql, params).fetchall()
    db.close()
    return [dict(r) for r in rows]

@app.post("/api/payslips/generate")
async def generate_payslips(request: Request, user=Depends(get_user)):
    """根据工时记录生成指定月份的工资条"""
    body = await request.json()
    month = body.get("month", datetime.now().strftime("%Y-%m"))
    db = database.get_db()
    try:
        rows = db.execute("""
            SELECT t.employee_id, e.name,
                   SUM(t.hours) AS total_hours,
                   SUM(t.hourly_pay) AS hourly_pay,
                   SUM(t.piece_pay) AS piece_pay,
                   SUM(t.perf_bonus) AS perf_bonus,
                   SUM(t.other_fee) AS other_bonus,
                   SUM(t.hourly_pay + t.piece_pay + t.perf_bonus + t.other_fee) AS gross_pay,
                   SUM(t.ssi_deduct) AS ssi_deduct,
                   SUM(t.tax_deduct) AS tax_deduct,
                   SUM(t.net_pay) AS net_pay
            FROM timesheet t
            JOIN employees e ON t.employee_id = e.id
            WHERE t.work_date LIKE ? || '%'
            GROUP BY t.employee_id
        """, (month,)).fetchall()
        count = 0
        for r in rows:
            pid = str(uuid.uuid4())
            db.execute("""
                INSERT OR REPLACE INTO payslips
                (id, employee_id, employee_name, month, total_hours, hourly_pay,
                 piece_pay, perf_bonus, other_bonus, gross_pay, ssi_deduct, tax_deduct,
                 other_deduct, net_pay, status, generated_by)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,0,?,'待确认',?)
            """, (pid, r["employee_id"], r["name"], month,
                  r["total_hours"], r["hourly_pay"], r["piece_pay"],
                  r["perf_bonus"], r["other_bonus"], r["gross_pay"],
                  r["ssi_deduct"], r["tax_deduct"], r["net_pay"],
                  user.get("display_name", "")))
            count += 1
        db.commit()
        return {"ok": True, "count": count, "month": month}
    except Exception as e:
        db.rollback()
        raise HTTPException(500, f"生成工资条失败: {str(e)}")
    finally:
        db.close()

@app.get("/api/mypage/payslips")
def get_my_payslips(user=Depends(get_user)):
    """获取当前员工的工资条"""
    eid = user.get("employee_id")
    if not eid:
        return []
    db = database.get_db()
    rows = db.execute(
        "SELECT * FROM payslips WHERE employee_id=? ORDER BY month DESC", (eid,)
    ).fetchall()
    db.close()
    return [dict(r) for r in rows]

@app.post("/api/payslips/{payslip_id}/confirm")
async def confirm_payslip(payslip_id: str, user=Depends(get_user)):
    """员工确认工资条"""
    db = database.get_db()
    try:
        db.execute(
            "UPDATE payslips SET confirmed_by_employee=1, confirmed_at=?, status='已确认' WHERE id=?",
            (datetime.now().isoformat(), payslip_id))
        db.commit()
        return {"ok": True}
    except Exception as e:
        db.rollback()
        raise HTTPException(500, str(e))
    finally:
        db.close()

# ── Salary Disputes - 薪资申诉 ──
@app.post("/api/payslips/{payslip_id}/dispute")
async def create_dispute(payslip_id: str, request: Request, user=Depends(get_user)):
    """员工对工资条提出申诉"""
    body = await request.json()
    reason = body.get("reason", "")
    db = database.get_db()
    try:
        db.execute(
            "UPDATE payslips SET status='申诉中', notes=? WHERE id=?",
            (reason, payslip_id))
        db.commit()
        audit_log(user.get("username", ""), "salary_dispute", "payslips", payslip_id, reason)
        return {"ok": True}
    except Exception as e:
        db.rollback()
        raise HTTPException(500, str(e))
    finally:
        db.close()

@app.post("/api/timesheet/{ts_id}/dispute")
async def create_timesheet_dispute(ts_id: str, request: Request, user=Depends(get_user)):
    """员工对工时记录提出申诉"""
    body = await request.json()
    reason = body.get("reason", "")
    db = database.get_db()
    try:
        db.execute(
            "UPDATE timesheet SET dispute_status='申诉中', dispute_reason=? WHERE id=?",
            (reason, ts_id))
        db.commit()
        audit_log(user.get("username", ""), "timesheet_dispute", "timesheet", ts_id, reason)
        return {"ok": True}
    except Exception as e:
        db.rollback()
        raise HTTPException(500, str(e))
    finally:
        db.close()

@app.post("/api/timesheet/{ts_id}/dispute-reply")
async def reply_timesheet_dispute(ts_id: str, request: Request, user=Depends(get_user)):
    """管理层回复工时申诉"""
    body = await request.json()
    reply = body.get("reply", "")
    status = body.get("status", "已处理")
    db = database.get_db()
    try:
        db.execute(
            "UPDATE timesheet SET dispute_status=?, dispute_reply=? WHERE id=?",
            (status, reply, ts_id))
        db.commit()
        return {"ok": True}
    except Exception as e:
        db.rollback()
        raise HTTPException(500, str(e))
    finally:
        db.close()

# ── Payroll Confirmation Flow - 工资确认流程 ──
@app.get("/api/payroll-confirmations")
def get_payroll_confirmations(month: Optional[str] = None, user=Depends(get_user)):
    """获取工资确认流程状态"""
    db = database.get_db()
    if month:
        rows = db.execute("SELECT * FROM payroll_confirmations WHERE month=? ORDER BY created_at", (month,)).fetchall()
    else:
        rows = db.execute("SELECT * FROM payroll_confirmations ORDER BY month DESC, created_at").fetchall()
    db.close()
    return [dict(r) for r in rows]

@app.post("/api/payroll-confirmations")
async def approve_payroll(request: Request, user=Depends(get_user)):
    """
    工资多级确认: step = leader/wh_manager/regional_manager/finance
    班组长 → 驻仓经理 → 区域经理 → 财务总监
    """
    body = await request.json()
    month = body.get("month", datetime.now().strftime("%Y-%m"))
    step = body.get("step")
    notes = body.get("notes", "")
    if step not in ("leader", "wh_manager", "regional_manager", "finance"):
        raise HTTPException(400, "无效的审批步骤")
    db = database.get_db()
    try:
        pid = str(uuid.uuid4())
        db.execute("""
            INSERT OR REPLACE INTO payroll_confirmations (id, month, step, status, approver, approve_time, notes)
            VALUES (?, ?, ?, '已审批', ?, ?, ?)
        """, (pid, month, step, user.get("display_name", ""), datetime.now().isoformat(), notes))
        db.commit()
        return {"ok": True, "month": month, "step": step}
    except Exception as e:
        db.rollback()
        raise HTTPException(500, str(e))
    finally:
        db.close()

@app.get("/api/payroll-preview")
def get_payroll_preview(month: Optional[str] = None, user=Depends(get_user)):
    """发薪前预览报表：汇总月度工资数据供财务核对"""
    if not month:
        month = datetime.now().strftime("%Y-%m")
    db = database.get_db()
    rows = db.execute("""
        SELECT t.employee_id, e.name, e.grade, e.primary_wh,
               COUNT(DISTINCT t.work_date) AS work_days,
               SUM(t.hours) AS total_hours,
               SUM(t.hourly_pay) AS total_hourly,
               SUM(t.piece_pay) AS total_piece,
               SUM(t.perf_bonus) AS total_perf,
               SUM(t.other_fee) AS total_other,
               SUM(t.hourly_pay + t.piece_pay + t.perf_bonus + t.other_fee) AS gross_pay,
               SUM(t.ssi_deduct) AS total_ssi,
               SUM(t.tax_deduct) AS total_tax,
               SUM(t.net_pay) AS net_pay,
               t.wh_status
        FROM timesheet t
        JOIN employees e ON t.employee_id = e.id
        WHERE t.work_date LIKE ? || '%'
        GROUP BY t.employee_id
        ORDER BY e.grade ASC, e.name ASC
    """, (month,)).fetchall()
    # Get confirmation status for this month
    confirmations = db.execute(
        "SELECT step, status, approver, approve_time FROM payroll_confirmations WHERE month=?", (month,)
    ).fetchall()
    db.close()
    return {
        "month": month,
        "employees": [dict(r) for r in rows],
        "confirmations": [dict(c) for c in confirmations],
        "total_count": len(rows),
        "total_gross": sum(r["gross_pay"] or 0 for r in rows),
        "total_net": sum(r["net_pay"] or 0 for r in rows)
    }

# ── Safety Incidents & Complaints - 安全事件与投诉 ──
@app.get("/api/safety-incidents")
def get_safety_incidents(warehouse_code: Optional[str] = None, status: Optional[str] = None, user=Depends(get_user)):
    db = database.get_db()
    sql = "SELECT * FROM safety_incidents WHERE 1=1"
    params = []
    if warehouse_code:
        sql += " AND warehouse_code=?"
        params.append(warehouse_code)
    if status:
        sql += " AND status=?"
        params.append(status)
    sql += " ORDER BY created_at DESC"
    rows = db.execute(sql, params).fetchall()
    db.close()
    return [dict(r) for r in rows]

@app.post("/api/safety-incidents")
async def create_safety_incident(request: Request, user=Depends(get_user)):
    data = await request.json()
    if not data.get("description"):
        raise HTTPException(400, "事件描述不能为空")
    if "id" not in data:
        data["id"] = f"SI-{uuid.uuid4().hex[:8]}"
    data.setdefault("incident_type", "安全事件")
    data.setdefault("severity", "一般")
    data.setdefault("status", "待处理")
    data.setdefault("reported_by", user.get("display_name", ""))
    data.setdefault("reported_date", datetime.now().strftime("%Y-%m-%d"))
    data.setdefault("created_at", datetime.now().isoformat())
    data.setdefault("updated_at", datetime.now().isoformat())
    try:
        insert("safety_incidents", data)
    except Exception as e:
        raise HTTPException(500, f"创建安全事件失败: {str(e)}")
    audit_log(user.get("username", ""), "create", "safety_incidents", data["id"], data.get("description", ""))
    return {"ok": True, "id": data["id"]}

@app.put("/api/safety-incidents/{incident_id}")
async def update_safety_incident(incident_id: str, request: Request, user=Depends(get_user)):
    data = await request.json()
    data["updated_at"] = datetime.now().isoformat()
    if data.get("status") == "已解决" and not data.get("resolved_date"):
        data["resolved_date"] = datetime.now().strftime("%Y-%m-%d")
    db = database.get_db()
    sets = ", ".join(f"{k}=?" for k in data)
    vals = list(data.values()) + [incident_id]
    db.execute(f"UPDATE safety_incidents SET {sets} WHERE id=?", vals)
    db.commit(); db.close()
    audit_log(user.get("username", ""), "update", "safety_incidents", incident_id, json.dumps(data, ensure_ascii=False))
    return {"ok": True}

# ── Org Chart - 组织架构 ──
@app.get("/api/org-chart")
def get_org_chart(user=Depends(get_user)):
    """获取组织架构数据，按职级层级和仓库分组"""
    db = database.get_db()
    employees = db.execute(
        "SELECT id, name, grade, position, primary_wh, source, supplier_id, status FROM employees WHERE status='在职' ORDER BY grade DESC, name"
    ).fetchall()
    warehouses = db.execute("SELECT code, name FROM warehouses").fetchall()
    db.close()

    grade_order = {"P9":0,"P8":1,"P7":2,"P6":3,"P5":4,"P4":5,"P3":6,"P2":7,"P1":8,"P0":9,
                   "M5":0,"M4":1,"M3":2,"M2":3,"M1":4}
    grade_titles = {
        "P9":"运营总监","P8":"区域经理","P7":"驻仓经理","P6":"副经理",
        "P5":"班组长","P4":"组长","P3":"技能工","P2":"资深操作员","P1":"操作员","P0":"供应商工人",
        "M5":"总监","M4":"高级经理","M3":"经理","M2":"主管","M1":"专员"
    }

    wh_map = {w["code"]: w["name"] for w in warehouses}
    emp_list = [dict(e) for e in employees]
    for e in emp_list:
        e["grade_order"] = grade_order.get(e["grade"], 99)
        e["grade_title"] = grade_titles.get(e["grade"], e["grade"])

    # Group by warehouse
    by_wh = {}
    for e in emp_list:
        wh = e.get("primary_wh") or "未分配"
        if wh not in by_wh:
            by_wh[wh] = {"code": wh, "name": wh_map.get(wh, wh), "employees": []}
        by_wh[wh]["employees"].append(e)

    # Sort each warehouse group by grade
    for wh_data in by_wh.values():
        wh_data["employees"].sort(key=lambda x: x["grade_order"])

    # Build hierarchy levels
    levels = [
        {"grade": "P9", "title": "运营总监 / Betriebsleiter", "employees": [e for e in emp_list if e["grade"] == "P9"]},
        {"grade": "P8", "title": "区域经理 / Regionalleiter", "employees": [e for e in emp_list if e["grade"] == "P8"]},
        {"grade": "P7", "title": "驻仓经理 / Lagerleiter", "employees": [e for e in emp_list if e["grade"] == "P7"]},
        {"grade": "P5/P6", "title": "班组长 / Schichtleiter", "employees": [e for e in emp_list if e["grade"] in ("P5", "P6")]},
        {"grade": "P4", "title": "组长 / Teamleiter", "employees": [e for e in emp_list if e["grade"] == "P4"]},
        {"grade": "P2/P3", "title": "小组长/技能工 / Facharbeiter", "employees": [e for e in emp_list if e["grade"] in ("P2", "P3")]},
        {"grade": "P0/P1", "title": "操作员 / Bediener", "employees": [e for e in emp_list if e["grade"] in ("P0", "P1")]},
    ]

    return {
        "levels": levels,
        "by_warehouse": list(by_wh.values()),
        "total": len(emp_list)
    }

# ── Employee Self-Registration - 新员工自助申报 ──
@app.post("/api/employee-register")
async def employee_self_register(request: Request):
    """新员工在线填写申报表格，无需登录。系统自动生成员工档案。
    Neue Mitarbeiter-Selbstregistrierung / New employee self-registration"""
    data = await request.json()
    if not data.get("name") and not (data.get("family_name") and data.get("given_name")):
        raise HTTPException(400, "姓名不能为空 / Name darf nicht leer sein")

    # Auto-generate employee ID from naming rules
    db = database.get_db()
    rule = db.execute("SELECT * FROM id_naming_rules WHERE id='default'").fetchone()
    if rule:
        prefix = rule["prefix"]
        sep = rule["separator"]
        next_num = rule["next_number"]
        pad = rule["padding"]
        eid = f"{prefix}{sep}{str(next_num).zfill(pad)}"
        db.execute("UPDATE id_naming_rules SET next_number=? WHERE id='default'", (next_num + 1,))
        db.commit()
    else:
        eid = f"YB-{uuid.uuid4().hex[:6].upper()}"
    db.close()

    # Build name from family_name + given_name if name not provided
    if not data.get("name"):
        data["name"] = f"{data.get('family_name', '')} {data.get('given_name', '')}".strip()

    data["id"] = eid
    data.setdefault("status", "在职")
    data.setdefault("grade", "P1")
    data.setdefault("position", "库内")
    data.setdefault("source", "自有")
    data.setdefault("tax_mode", "我方报税")
    data.setdefault("join_date", datetime.now().strftime("%Y-%m-%d"))
    data.setdefault("created_at", datetime.now().isoformat())
    data.setdefault("updated_at", datetime.now().isoformat())

    try:
        insert("employees", data)
    except Exception as e:
        raise HTTPException(500, f"创建员工失败: {str(e)}")

    return {"ok": True, "id": eid, "message": f"员工档案已创建 / Mitarbeiterakte erstellt: {eid}"}

# ── ID Naming Rules - 员工ID命名规则 ──
@app.get("/api/id-naming-rules")
def get_id_naming_rules(user=Depends(get_user)):
    db = database.get_db()
    rows = db.execute("SELECT * FROM id_naming_rules").fetchall()
    db.close()
    return [dict(r) for r in rows]

@app.put("/api/id-naming-rules")
async def update_id_naming_rules(request: Request, user=Depends(get_user)):
    """管理员修改员工ID命名规则"""
    data = await request.json()
    data["updated_by"] = user.get("username", "")
    data["updated_at"] = datetime.now().isoformat()
    db = database.get_db()
    db.execute(
        "UPDATE id_naming_rules SET prefix=?, separator=?, next_number=?, padding=?, description=?, updated_by=?, updated_at=? WHERE id='default'",
        (data.get("prefix", "YB"), data.get("separator", "-"), data.get("next_number", 1),
         data.get("padding", 3), data.get("description", ""), data["updated_by"], data["updated_at"])
    )
    db.commit(); db.close()
    audit_log(user.get("username", ""), "update", "id_naming_rules", "default", json.dumps(data, ensure_ascii=False))
    return {"ok": True}

# ── Compliance Check - 合规检查 ──
@app.get("/api/compliance/work-hours")
def check_work_hours_compliance(month: Optional[str] = None, user=Depends(get_user)):
    """检查员工工时是否符合德国劳动法 / Überprüfung der Arbeitszeitkonformität"""
    if not month:
        month = datetime.now().strftime("%Y-%m")
    db = database.get_db()
    # Check daily violations (>10h)
    daily_violations = db.execute("""
        SELECT employee_id, employee_name, work_date, warehouse_code, hours
        FROM timesheet WHERE work_date LIKE ? || '%' AND hours > 10
        ORDER BY work_date, employee_id
    """, (month,)).fetchall()
    # Check weekly totals
    weekly_data = db.execute("""
        SELECT employee_id, employee_name,
               strftime('%%W', work_date) as week_num,
               SUM(hours) as total_hours,
               COUNT(*) as work_days
        FROM timesheet WHERE work_date LIKE ? || '%'
        GROUP BY employee_id, week_num
        HAVING total_hours > 48
        ORDER BY total_hours DESC
    """, (month,)).fetchall()
    db.close()
    return {
        "month": month,
        "daily_violations": [dict(r) for r in daily_violations],
        "weekly_violations": [dict(r) for r in weekly_data],
        "daily_count": len(daily_violations),
        "weekly_count": len(weekly_data),
        "compliant": len(daily_violations) == 0 and len(weekly_data) == 0
    }

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
