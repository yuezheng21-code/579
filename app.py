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
            # Auto-backup existing data before upgrade/reinitialization
            backup_path = database.auto_backup_before_upgrade()
            if backup_path:
                print(f"📦 Pre-upgrade backup created: {backup_path}")

            database.init_db()
            database.seed_data()
            database.ensure_demo_users()

            # Auto-restore user data from backup after upgrade
            if backup_path:
                summary = database.auto_restore_after_upgrade(backup_path)
                if summary:
                    print(f"♻️ Data restored after upgrade: {sum(summary.values())} rows across {len(summary)} tables")

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

@app.middleware("http")
async def db_ready_middleware(request: Request, call_next):
    """Block API requests while database is still initializing.
    Static files and health checks are always allowed."""
    path = request.url.path
    if not _db_ready and path.startswith("/api/") and path != "/api/health":
        return JSONResponse(
            status_code=503,
            content={"detail": "数据库正在初始化，请稍后再试 (Database initializing, please retry)"},
        )
    return await call_next(request)

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
    "dispatch_transfers", "regions", "job_positions", "cloud_sync_configs"
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
    "regions": ["code", "name", "created_at", "updated_at"],
    "job_positions": ["code", "level", "category", "created_at", "updated_at"],
    "cloud_sync_configs": ["id", "created_at", "updated_at", "provider", "name"],
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
        if limit <= 0 or limit > 5000:
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
        try:
            # Use the actual schema of audit_logs table
            db.execute("""
                INSERT INTO audit_logs (username, action, target_table, target_id, new_value)
                VALUES (?, ?, ?, ?, ?)
            """, (username, action, resource_type, resource_id, details))
            db.commit()
        finally:
            db.close()
    except Exception as e:
        # Log the failure but don't fail the operation
        import sys
        print(f"AUDIT LOG FAILURE: {username} {action} {resource_type}/{resource_id} - Error: {e}", file=sys.stderr)

# Foreign key columns in the employees table that must be NULL (not empty string) when unset
_EMPLOYEE_FK_COLUMNS = ("primary_wh", "supplier_id", "grade")

def _sanitize_employee_fk_fields(data: dict) -> dict:
    """Convert empty string FK values to None to avoid FK constraint violations."""
    for fk_col in _EMPLOYEE_FK_COLUMNS:
        if fk_col in data and data[fk_col] == "":
            data[fk_col] = None
    return data

# ── Master Table Cascade Sync (主表联动) ──
# NOTE: These cascade functions modify the database but do NOT commit.
# The caller is responsible for committing the transaction to ensure atomicity.
def _cascade_employee_to_users(eid: str, data: dict, db):
    """When employee master record changes, sync key fields to linked users table.
    花名册 → 用户账号 联动同步"""
    sync_map = {
        "primary_wh": "warehouse_code",
        "supplier_id": "supplier_id",
        "name": "display_name",
        "biz_line": "biz_line",
    }
    updates = {}
    for emp_field, user_field in sync_map.items():
        if emp_field in data:
            updates[user_field] = data[emp_field]
    if not updates:
        return
    sets = ",".join(f"{k}=?" for k in updates.keys())
    db.execute(f"UPDATE users SET {sets} WHERE employee_id=?",
               list(updates.values()) + [eid])

def _cascade_warehouse_to_users(code: str, data: dict, db):
    """When warehouse master record changes, sync region to users linked by warehouse_code.
    仓库设置 → 用户账号 联动同步"""
    # If warehouse name changes, no column in users to update, but we sync biz_line if present
    if "biz_line" in data:
        db.execute("UPDATE users SET biz_line=? WHERE warehouse_code=?",
                   (data["biz_line"], code))

def _cascade_warehouse_to_employees(code: str, data: dict, db):
    """When warehouse master record changes, sync key fields to linked employees.
    仓库设置 → 花名册 联动同步"""
    if "biz_line" in data:
        db.execute("UPDATE employees SET biz_line=? WHERE primary_wh=?",
                   (data["biz_line"], code))

def _cascade_supplier_to_users(sid: str, data: dict, db):
    """When supplier master record changes, sync display_name to users linked by supplier_id.
    供应商 → 用户账号 联动同步"""
    if "name" in data:
        db.execute("UPDATE users SET display_name=? WHERE supplier_id=? AND employee_id IS NULL",
                   (data["name"], sid))

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
    try:
        u = db.execute("SELECT * FROM users WHERE username=? AND active=1", (req.username,)).fetchone()
    finally:
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
    try:
        emp = db.execute("SELECT * FROM employees WHERE pin=?", (req.pin,)).fetchone()
    finally:
        db.close()
    if not emp: raise HTTPException(401, "PIN无效")
    token = make_token(emp["id"], "worker", {"pin": 1})
    return {"token": token, "user": {"username": emp["id"], "display_name": emp["name"], "role": "worker", "employee_id": emp["id"]}}

# ── Employees ──
_EMP_JOIN_SQL = """SELECT e.*, s.name as supplier_name, w.name as warehouse_name,
    g.title_zh as grade_title
    FROM employees e
    LEFT JOIN suppliers s ON s.id = e.supplier_id
    LEFT JOIN warehouses w ON w.code = e.primary_wh
    LEFT JOIN grade_levels g ON g.code = e.grade"""

@app.get("/api/employees")
def get_employees(user=Depends(get_user)):
    role = user.get("role", "worker")
    db = database.get_db()
    try:
        # Supplier users can only see their own workers
        if role == "sup" and user.get("supplier_id"):
            rows = db.execute(f"{_EMP_JOIN_SQL} WHERE e.supplier_id=? ORDER BY e.id DESC",
                              (user["supplier_id"],)).fetchall()
        # Warehouse users can only see employees in their warehouse
        elif role == "wh" and user.get("warehouse_code"):
            wh = user["warehouse_code"]
            rows = db.execute(f"{_EMP_JOIN_SQL} WHERE e.primary_wh=? OR e.dispatch_whs LIKE ? ORDER BY e.id DESC",
                              (wh, f"%{wh}%")).fetchall()
        else:
            # 根据职级、部门、仓库做权限过滤
            emp_ids, scope = _get_scoped_employee_ids(user)
            if scope == "all":
                rows = db.execute(f"{_EMP_JOIN_SQL} ORDER BY e.id DESC").fetchall()
            elif emp_ids is not None and len(emp_ids) > 0:
                placeholders = ",".join(["?"] * len(emp_ids))
                rows = db.execute(f"{_EMP_JOIN_SQL} WHERE e.id IN ({placeholders}) ORDER BY e.id DESC",
                                  tuple(emp_ids)).fetchall()
            elif emp_ids is not None:
                rows = []
            else:
                rows = db.execute(f"{_EMP_JOIN_SQL} ORDER BY e.id DESC").fetchall()
        rows = [dict(r) for r in rows]
    finally:
        db.close()
    return _filter_hidden_fields(rows, role, "employees")

@app.get("/api/employees/{eid}")
def get_employee(eid: str, user=Depends(get_user)):
    db = database.get_db()
    try:
        rows = db.execute(f"{_EMP_JOIN_SQL} WHERE e.id=?", (eid,)).fetchall()
        emps = [dict(r) for r in rows]
    finally:
        db.close()
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
    _sanitize_employee_fk_fields(data)
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
        VALID_ROLES = set(ROLE_HIERARCHY.keys())
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
                 employee_id, data.get("primary_wh") or None, data.get("biz_line", "")))
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
    # Strip virtual/JOINed fields that are not actual columns in employees table
    for vf in ("supplier_name", "warehouse_name", "grade_title"):
        data.pop(vf, None)
    role = user.get("role", "worker")
    data = _enforce_editable_fields(data, role, "employees")
    if not data:
        raise HTTPException(403, "无可编辑字段")
    _sanitize_employee_fk_fields(data)
    db = database.get_db()
    try:
        sets = ",".join(f"{k}=?" for k in data.keys())
        db.execute(f"UPDATE employees SET {sets} WHERE id=?", list(data.values()) + [eid])
        # 主表联动: 花名册变更 → 同步用户账号
        _cascade_employee_to_users(eid, data, db)
        db.commit()
    except Exception as e:
        db.rollback()
        raise HTTPException(500, f"更新员工失败: {str(e)}")
    finally:
        db.close()
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
    try:
        rows = db.execute(f"""
            SELECT e.*, s.name as supplier_name, w.name as warehouse_name, w.service_type,
                g.title_zh as grade_title
            FROM employees e
            LEFT JOIN suppliers s ON s.id = e.supplier_id
            LEFT JOIN warehouses w ON w.code = e.primary_wh
            LEFT JOIN grade_levels g ON g.code = e.grade
            WHERE {where}
            ORDER BY e.id ASC
        """, tuple(params)).fetchall()
    finally:
        db.close()
    result = [dict(r) for r in rows]
    return _filter_hidden_fields(result, role, "employees")

@app.get("/api/roster/stats")
def get_roster_stats(user=Depends(get_user)):
    """花名册统计 - 按派遣类型、合同类型、来源等统计"""
    db = database.get_db()
    try:
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
            "id_expiring_soon": [dict(r) for r in db.execute(
                "SELECT id, name, id_type, id_number, id_expiry_date, nationality FROM employees WHERE status='在职' AND id_expiry_date IS NOT NULL AND id_expiry_date <= date('now', '+90 days') ORDER BY id_expiry_date ASC"
            ).fetchall()],
        }
    finally:
        db.close()
    return stats

@app.get("/api/expiry-warnings")
def get_expiry_warnings(user=Depends(get_user)):
    """获取所有即将到期的证件和工作许可预警（三个月内）"""
    db = database.get_db()
    try:
        warnings = []
        # Work permit expiry
        rows = db.execute(
            "SELECT id, name, work_permit_no, work_permit_expiry, nationality, primary_wh FROM employees "
            "WHERE status='在职' AND work_permit_expiry IS NOT NULL AND work_permit_expiry <= date('now', '+90 days') "
            "ORDER BY work_permit_expiry ASC"
        ).fetchall()
        for r in rows:
            d = dict(r)
            d["warning_type"] = "work_permit"
            d["expiry_date"] = d["work_permit_expiry"]
            warnings.append(d)
        # ID document expiry
        rows = db.execute(
            "SELECT id, name, id_type, id_number, id_expiry_date, nationality, primary_wh FROM employees "
            "WHERE status='在职' AND id_expiry_date IS NOT NULL AND id_expiry_date <= date('now', '+90 days') "
            "ORDER BY id_expiry_date ASC"
        ).fetchall()
        for r in rows:
            d = dict(r)
            d["warning_type"] = "id_document"
            d["expiry_date"] = d["id_expiry_date"]
            warnings.append(d)
        # Contract expiry
        rows = db.execute(
            "SELECT id, name, contract_end, primary_wh FROM employees "
            "WHERE status='在职' AND contract_end IS NOT NULL AND contract_end <= date('now', '+90 days') "
            "ORDER BY contract_end ASC"
        ).fetchall()
        for r in rows:
            d = dict(r)
            d["warning_type"] = "contract"
            d["expiry_date"] = d["contract_end"]
            warnings.append(d)
    finally:
        db.close()
    warnings.sort(key=lambda x: x.get("expiry_date") or "9999-12-31")
    return warnings

# ── Account Management ──
@app.get("/api/accounts")
def get_accounts(user=Depends(get_user)):
    """获取所有员工账号状态"""
    db = database.get_db()
    try:
        rows = db.execute("""
            SELECT e.id, e.name, e.grade, e.primary_wh, e.status, e.has_account,
                   u.username, u.role, u.active as account_active
            FROM employees e
            LEFT JOIN users u ON u.employee_id = e.id
            WHERE e.status = '在职'
            ORDER BY e.id
        """).fetchall()
    finally:
        db.close()
    return [dict(r) for r in rows]

@app.post("/api/accounts/generate")
async def generate_account(request: Request, user=Depends(get_user)):
    """为员工生成账号"""
    data = await request.json()
    employee_id = data.get("employee_id")
    role = data.get("role", "worker")

    db = database.get_db()
    try:
        emp = db.execute("SELECT * FROM employees WHERE id=?", (employee_id,)).fetchone()
        if not emp:
            raise HTTPException(404, "员工不存在")

        # 检查是否已有账号
        existing = db.execute("SELECT * FROM users WHERE employee_id=?", (employee_id,)).fetchone()
        if existing:
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
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(500, f"生成账号失败: {str(e)}")
    finally:
        db.close()

    return {"ok": True, "username": username, "password": password, "display_name": emp["name"]}

@app.post("/api/accounts/batch-generate")
async def batch_generate_accounts(request: Request, user=Depends(get_user)):
    """批量生成账号"""
    data = await request.json()
    employee_ids = data.get("employee_ids", [])
    role = data.get("role", "worker")

    if not employee_ids:
        return {"ok": True, "accounts": []}

    results = []
    db = database.get_db()
    
    try:
        # Batch-fetch all employees and existing users to avoid N+1 queries
        placeholders = ",".join(["?"] * len(employee_ids))
        emp_rows = db.execute(
            f"SELECT id, name, primary_wh, biz_line FROM employees WHERE id IN ({placeholders})",
            employee_ids
        ).fetchall()
        emp_map = {r["id"]: r for r in emp_rows}

        existing_rows = db.execute(
            f"SELECT employee_id FROM users WHERE employee_id IN ({placeholders})",
            employee_ids
        ).fetchall()
        existing_set = {r["employee_id"] for r in existing_rows}

        for eid in employee_ids:
            emp = emp_map.get(eid)
            if not emp or eid in existing_set:
                continue

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

@app.put("/api/accounts/{username}")
async def update_account(username: str, request: Request, user=Depends(get_user)):
    """修改账号信息（角色、显示名、仓库、业务线等）"""
    if user.get("role") != "admin":
        raise HTTPException(403, "仅管理员可修改账号信息")

    data = await request.json()
    allowed_fields = {"role", "display_name", "warehouse_code", "biz_line", "supplier_id", "color", "avatar"}
    updates = {k: v for k, v in data.items() if k in allowed_fields}
    if not updates:
        raise HTTPException(400, "无有效更新字段")

    # Validate role if being changed
    if "role" in updates and updates["role"] not in ROLE_HIERARCHY:
        raise HTTPException(400, f"无效角色: {updates['role']}")

    db = database.get_db()
    try:
        u = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        if not u:
            raise HTTPException(404, "账号不存在")

        set_clauses = ", ".join(f"{k}=?" for k in updates)
        values = list(updates.values()) + [username]
        db.execute(f"UPDATE users SET {set_clauses} WHERE username=?", values)
        db.commit()
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(500, f"更新账号失败: {str(e)}")
    finally:
        db.close()

    audit_log(user.get("username", ""), "update_account", "user", username,
              f"账号信息更新: {json.dumps(updates, ensure_ascii=False)}")

    return {"ok": True, "updated": updates}

@app.delete("/api/accounts/{username}")
async def delete_account(username: str, user=Depends(get_user)):
    """删除账号"""
    if user.get("role") != "admin":
        raise HTTPException(403, "仅管理员可删除账号")

    if username == user.get("username"):
        raise HTTPException(400, "不能删除自己的账号")

    db = database.get_db()
    try:
        u = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        if not u:
            raise HTTPException(404, "账号不存在")

        employee_id = u["employee_id"]
        db.execute("DELETE FROM users WHERE username=?", (username,))
        if employee_id:
            db.execute("UPDATE employees SET has_account=0 WHERE id=?", (employee_id,))
        db.commit()
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(500, f"删除账号失败: {str(e)}")
    finally:
        db.close()

    audit_log(user.get("username", ""), "delete_account", "user", username,
              f"账号已删除由 {user.get('username')} 执行")

    return {"ok": True}

@app.post("/api/accounts/{username}/set-password")
async def set_account_password(username: str, request: Request, user=Depends(get_user)):
    """管理员设置账号密码"""
    if user.get("role") != "admin":
        raise HTTPException(403, "仅管理员可设置密码")

    data = await request.json()
    new_password = data.get("password", "").strip()
    if len(new_password) < 6:
        raise HTTPException(400, "密码长度不能少于6位")

    db = database.get_db()
    try:
        u = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        if not u:
            raise HTTPException(404, "账号不存在")

        password_hash = hash_password(new_password)
        db.execute("UPDATE users SET password_hash=? WHERE username=?", (password_hash, username))
        db.commit()
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(500, f"设置密码失败: {str(e)}")
    finally:
        db.close()

    audit_log(user.get("username", ""), "set_password", "user", username,
              f"密码由管理员 {user.get('username')} 手动设置")

    return {"ok": True}

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

    # 获取各仓库的薪资配置 (batch query instead of per-warehouse)
    configs = []
    if wh_list:
        placeholders = ",".join(["?"] * len(wh_list))
        cfg_rows = db.execute(f"""
            SELECT wsc.*, w.name as warehouse_name
            FROM warehouse_salary_config wsc
            JOIN warehouses w ON w.code = wsc.warehouse_code
            WHERE wsc.warehouse_code IN ({placeholders}) AND wsc.grade=?
        """, wh_list + [emp["grade"]]).fetchall()
        configs = [dict(c) for c in cfg_rows]

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
    db = database.get_db()
    try:
        sets = ",".join(f"{k}=?" for k in data.keys())
        db.execute(f"UPDATE suppliers SET {sets} WHERE id=?", list(data.values()) + [sid])
        # 主表联动: 供应商变更 → 同步用户账号
        _cascade_supplier_to_users(sid, data, db)
        db.commit()
    except Exception as e:
        db.rollback()
        raise HTTPException(500, f"更新供应商失败: {str(e)}")
    finally:
        db.close()
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
    db = database.get_db()
    try:
        sets = ",".join(f"{k}=?" for k in data.keys())
        db.execute(f"UPDATE warehouses SET {sets} WHERE code=?", list(data.values()) + [code])
        # 主表联动: 仓库设置变更 → 同步用户账号 & 花名册
        _cascade_warehouse_to_users(code, data, db)
        _cascade_warehouse_to_employees(code, data, db)
        db.commit()
    except Exception as e:
        db.rollback()
        raise HTTPException(500, f"更新仓库失败: {str(e)}")
    finally:
        db.close()
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
        from datetime import date as dt_date
        try:
            parts = work_date.split("-")
            d = dt_date(int(parts[0]), int(parts[1]), int(parts[2]))
        except (ValueError, IndexError):
            raise HTTPException(400, f"工作日期格式无效: {work_date}，请使用YYYY-MM-DD格式 / Ungültiges Datumsformat")
        week_start = (d - timedelta(days=d.weekday())).isoformat()
        week_end = (d + timedelta(days=6 - d.weekday())).isoformat()
        db = database.get_db()
        try:
            weekly = db.execute(
                "SELECT COALESCE(SUM(hours),0) as total FROM timesheet WHERE employee_id=? AND work_date>=? AND work_date<=?",
                (employee_id, week_start, week_end)
            ).fetchone()
            weekly_total = (weekly["total"] if weekly else 0) + hours
        finally:
            db.close()
        if weekly_total > MAX_WEEKLY_HOURS:
            raise HTTPException(400, f"该员工本周已工作{weekly_total-hours}小时，加上本次{hours}小时共{weekly_total}小时，超过德国劳动法{MAX_WEEKLY_HOURS}小时/周上限 / Wöchentliche Arbeitszeit würde {MAX_WEEKLY_HOURS} Stunden überschreiten")

    # 检查是否已存在相同的工时记录
    if employee_id and work_date and warehouse_code:
        db = database.get_db()
        try:
            existing = db.execute("""
                SELECT id FROM timesheet 
                WHERE employee_id=? AND work_date=? AND warehouse_code=?
            """, (employee_id, work_date, warehouse_code)).fetchone()
        finally:
            db.close()
        
        if existing:
            raise HTTPException(400, f"该员工在该日期和仓库已有工时记录 (ID: {existing['id']})")

    # 根据仓库获取薪资配置
    wh = data.get("warehouse_code")
    grade = data.get("grade")
    position = data.get("position", "库内")

    if wh and grade:
        db = database.get_db()
        try:
            cfg = db.execute("""
                SELECT * FROM warehouse_salary_config
                WHERE warehouse_code=? AND grade=? AND position_type=?
            """, (wh, grade, position)).fetchone()

            if cfg:
                data["base_rate"] = cfg["hourly_rate"]
                # 计算应付工资
                hours = float(data.get("hours", 0))
                data["hourly_pay"] = round(cfg["hourly_rate"] * hours, 2)
        finally:
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
    try:
        rows = db.execute(
            """
            SELECT t.employee_id, e.name, e.grade,
                   SUM(t.hours) AS total_hours,
                   SUM(t.hourly_pay) AS total_gross,
                   SUM(t.net_pay) AS total_net
            FROM timesheet t
            JOIN employees e ON t.employee_id = e.id
            WHERE t.work_date LIKE ?
            GROUP BY t.employee_id
            ORDER BY e.grade ASC, e.name ASC
            """,
            (f"{month}%",)
        ).fetchall()
    finally:
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

@app.post("/api/quotation-pdf")
async def generate_quotation_pdf(request: Request, user=Depends(get_user)):
    """Generate a PDF document for selected quotation records (组合报价)."""
    body = await request.json()
    ids = body.get("ids", [])
    if not ids or not isinstance(ids, list):
        raise HTTPException(400, "请选择至少一条报价记录")
    # Sanitize: only allow expected ID format
    for rid in ids:
        if not isinstance(rid, str) or len(rid) > 50:
            raise HTTPException(400, "无效的报价ID")
    db = database.get_db()
    placeholders = ",".join(["?"] * len(ids))
    rows = db.execute(f"SELECT * FROM quotation_records WHERE id IN ({placeholders})", ids).fetchall()
    db.close()
    if not rows:
        raise HTTPException(404, "未找到报价记录")
    records = [dict(r) for r in rows]
    # Fetch templates for reference
    tpl_ids = list(set(r.get("template_id") or "" for r in records if r.get("template_id")))
    tpl_map = {}
    if tpl_ids:
        db2 = database.get_db()
        ph2 = ",".join(["?"] * len(tpl_ids))
        tpl_rows = db2.execute(f"SELECT * FROM quotation_templates WHERE id IN ({ph2})", tpl_ids).fetchall()
        db2.close()
        tpl_map = {t["id"]: dict(t) for t in tpl_rows}

    import io
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.units import mm
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, topMargin=20*mm, bottomMargin=15*mm,
                            leftMargin=15*mm, rightMargin=15*mm)

    # Try to register a CJK font for Chinese characters
    font_name = "Helvetica"
    bold_font = "Helvetica-Bold"
    try:
        from reportlab.pdfbase.cidfonts import UnicodeCIDFont
        pdfmetrics.registerFont(UnicodeCIDFont("STSong-Light"))
        font_name = "STSong-Light"
        bold_font = "STSong-Light"
    except Exception:
        pass

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("CNTitle", parent=styles["Title"], fontName=bold_font, fontSize=18)
    normal_style = ParagraphStyle("CNNormal", parent=styles["Normal"], fontName=font_name, fontSize=9)
    header_style = ParagraphStyle("CNHeader", parent=styles["Normal"], fontName=bold_font, fontSize=11)

    elements = []
    elements.append(Paragraph("组合报价单", title_style))
    elements.append(Spacer(1, 5*mm))

    gen_date = datetime.now().strftime("%Y-%m-%d %H:%M")
    gen_user = user.get("username", "")
    elements.append(Paragraph(f"生成日期: {gen_date}    操作人: {gen_user}    报价数量: {len(records)}", normal_style))
    elements.append(Spacer(1, 5*mm))

    # Summary table
    header_row = ["报价号", "客户", "业务类型", "服务类型", "仓库", "人数", "单价(€)", "总额(€)", "审批状态"]
    table_data = [header_row]
    grand_total = 0
    for r in records:
        table_data.append([
            str(r.get("id", "")),
            str(r.get("client_name", "")),
            str(r.get("biz_type", "")),
            str(r.get("service_type", "")),
            str(r.get("warehouse_code", "")),
            str(r.get("headcount", "")),
            str(r.get("final_price", "")),
            str(r.get("total_amount", "")),
            str(r.get("approve_status", "")),
        ])
        try:
            grand_total += float(r.get("total_amount", 0) or 0)
        except (ValueError, TypeError):
            pass
    # Add total row
    table_data.append(["", "", "", "", "", "", "合计:", f"€{grand_total:.2f}", ""])

    col_widths = [55, 55, 50, 50, 45, 30, 45, 50, 50]
    t = Table(table_data, colWidths=col_widths)
    t.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (-1, -1), font_name),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("FONTNAME", (0, 0), (-1, 0), bold_font),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#4a90d9")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("ALIGN", (5, 0), (-1, -1), "CENTER"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("ROWBACKGROUNDS", (0, 1), (-1, -2), [colors.white, colors.HexColor("#f0f4f8")]),
        ("FONTNAME", (0, -1), (-1, -1), bold_font),
        ("BACKGROUND", (0, -1), (-1, -1), colors.HexColor("#e8edf2")),
    ]))
    elements.append(t)
    elements.append(Spacer(1, 8*mm))

    # Detail sections for each record
    for r in records:
        elements.append(Paragraph(f"报价明细 — {r.get('id','')}", header_style))
        elements.append(Spacer(1, 2*mm))
        detail = [
            ["客户名称", str(r.get("client_name", "")), "联系人", str(r.get("client_contact", ""))],
            ["业务类型", str(r.get("biz_type", "")), "服务类型", str(r.get("service_type", ""))],
            ["仓库", str(r.get("warehouse_code", "")), "报价日期", str(r.get("quote_date", ""))],
            ["人数", str(r.get("headcount", "")), "预计工时", str(r.get("estimated_hours", ""))],
            ["基础单价", f"€{r.get('base_price','0')}", "最终单价", f"€{r.get('final_price','0')}"],
            ["总金额", f"€{r.get('total_amount','0')}", "币种", str(r.get("currency", "EUR"))],
            ["有效期至", str(r.get("valid_until", "")), "合同编号", str(r.get("contract_no", ""))],
            ["审核状态", str(r.get("review_status", "")), "审批状态", str(r.get("approve_status", ""))],
        ]
        tpl = tpl_map.get(r.get("template_id"))
        if tpl:
            detail.append(["报价模板", str(tpl.get("name", "")), "模板单价", f"€{tpl.get('base_price','0')}"])
            surcharges = f"夜班+€{tpl.get('night_surcharge',0)} 周末+€{tpl.get('weekend_surcharge',0)} 节假+€{tpl.get('holiday_surcharge',0)}"
            detail.append(["附加费", surcharges, "", ""])
        if r.get("notes"):
            detail.append(["备注", str(r.get("notes", "")), "", ""])
        dt = Table(detail, colWidths=[60, 120, 60, 120])
        dt.setStyle(TableStyle([
            ("FONTNAME", (0, 0), (-1, -1), font_name),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("FONTNAME", (0, 0), (0, -1), bold_font),
            ("FONTNAME", (2, 0), (2, -1), bold_font),
            ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#4a90d9")),
            ("TEXTCOLOR", (2, 0), (2, -1), colors.HexColor("#4a90d9")),
            ("GRID", (0, 0), (-1, -1), 0.3, colors.lightgrey),
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f5f7fa")),
            ("BACKGROUND", (2, 0), (2, -1), colors.HexColor("#f5f7fa")),
        ]))
        elements.append(dt)
        elements.append(Spacer(1, 5*mm))

    doc.build(elements)
    pdf_bytes = buf.getvalue()
    buf.close()

    from fastapi.responses import Response
    filename = f"quotation_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    return Response(content=pdf_bytes, media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="{filename}"'})

# ── Employee Files ──

# Roles that can view all employee files
_FILE_FULL_ACCESS_ROLES = {"admin", "ceo", "hr", "hr_manager", "hr_assistant", "hr_specialist",
                            "fin", "fin_director", "fin_assistant", "fin_specialist",
                            "regional_mgr", "ops_director"}

def _can_access_employee_files(user, target_employee_id: str) -> bool:
    """Check if user can access files for a given employee.
    - admin/ceo/hr/finance roles: full access
    - P8-P9 grade employees: full access
    - P5-P7 ops roles: access files of employees in their warehouse
    - workers: own files only
    """
    role = user.get("role", "worker")
    if role in _FILE_FULL_ACCESS_ROLES:
        return True
    # Check grade-based access (P8-P9)
    emp_id = user.get("employee_id")
    if emp_id:
        db = database.get_db()
        try:
            emp = db.execute("SELECT grade, primary_wh FROM employees WHERE id=?", (emp_id,)).fetchone()
            if emp:
                grade = (emp["grade"] or "P1").upper()
                grade_num = int(grade.replace("P", "").replace("M", "")) if grade[0] in ("P", "M") else 0
                if grade_num >= 8:
                    return True
                # P5-P7: can access files of employees in their warehouse
                if grade_num >= 5 and emp["primary_wh"]:
                    target = db.execute("SELECT primary_wh FROM employees WHERE id=?", (target_employee_id,)).fetchone()
                    if target and target["primary_wh"] == emp["primary_wh"]:
                        return True
        finally:
            db.close()
    # Warehouse managers: employees in their warehouse
    if role in ("wh", "site_mgr", "shift_leader", "deputy_mgr") and user.get("warehouse_code"):
        db = database.get_db()
        try:
            target = db.execute("SELECT primary_wh FROM employees WHERE id=?", (target_employee_id,)).fetchone()
            if target and target["primary_wh"] == user["warehouse_code"]:
                return True
        finally:
            db.close()
    # Worker: own files only
    if user.get("employee_id") == target_employee_id:
        return True
    return False

@app.get("/api/files")
def get_files(employee_id: Optional[str] = None, user=Depends(get_user)):
    """获取员工文件列表，权限控制：
    - 员工只能看自己的文件
    - 财务/人事可以看所有人
    - 运营P5-P7看所在仓库人员
    - P8-P9和CEO可以看所有人
    """
    role = user.get("role", "worker")
    # Full access roles get all files
    if role in _FILE_FULL_ACCESS_ROLES:
        if employee_id:
            return q("employee_files", "employee_id=?", (employee_id,))
        return q("employee_files")
    # Check grade-based full access (P8-P9)
    emp_id = user.get("employee_id")
    if emp_id:
        db = database.get_db()
        try:
            emp = db.execute("SELECT grade FROM employees WHERE id=?", (emp_id,)).fetchone()
            if emp:
                grade = (emp["grade"] or "P1").upper()
                grade_num = int(grade.replace("P", "").replace("M", "")) if grade[0] in ("P", "M") else 0
                if grade_num >= 8:
                    if employee_id:
                        return q("employee_files", "employee_id=?", (employee_id,))
                    return q("employee_files")
        finally:
            db.close()
    # If specific employee_id requested, check access
    if employee_id:
        if not _can_access_employee_files(user, employee_id):
            raise HTTPException(403, "无权访问该员工文件")
        return q("employee_files", "employee_id=?", (employee_id,))
    # For warehouse-scoped roles, return files of their warehouse employees
    wh_code = user.get("warehouse_code")
    if wh_code and role in ("wh", "site_mgr", "shift_leader", "deputy_mgr"):
        db = database.get_db()
        try:
            rows = db.execute(
                "SELECT ef.* FROM employee_files ef JOIN employees e ON ef.employee_id=e.id WHERE e.primary_wh=?",
                (wh_code,)).fetchall()
        finally:
            db.close()
        return [dict(r) for r in rows]
    # P5-P7 with warehouse: return warehouse files
    if emp_id:
        db = database.get_db()
        try:
            emp = db.execute("SELECT grade, primary_wh FROM employees WHERE id=?", (emp_id,)).fetchone()
            if emp:
                grade = (emp["grade"] or "P1").upper()
                grade_num = int(grade.replace("P", "").replace("M", "")) if grade[0] in ("P", "M") else 0
                if grade_num >= 5 and emp["primary_wh"]:
                    rows = db.execute(
                        "SELECT ef.* FROM employee_files ef JOIN employees e ON ef.employee_id=e.id WHERE e.primary_wh=?",
                        (emp["primary_wh"],)).fetchall()
                    return [dict(r) for r in rows]
        finally:
            db.close()
    # Default: worker sees own files only
    if emp_id:
        return q("employee_files", "employee_id=?", (emp_id,))
    return []

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

@app.get("/api/files/{file_id}/download")
def download_single_file(file_id: str, user=Depends(get_user)):
    """下载单个员工文件"""
    db = database.get_db()
    try:
        f = db.execute("SELECT * FROM employee_files WHERE id=?", (file_id,)).fetchone()
    finally:
        db.close()
    if not f:
        raise HTTPException(404, "文件不存在")
    f = dict(f)
    if not _can_access_employee_files(user, f["employee_id"]):
        raise HTTPException(403, "无权下载该文件")
    file_url = f.get("file_url") or ""
    if file_url.startswith("/uploads/"):
        file_path = os.path.join(UPLOAD_DIR, file_url.replace("/uploads/", "", 1))
        if os.path.isfile(file_path):
            return FileResponse(file_path, filename=f.get("file_name") or os.path.basename(file_path))
    raise HTTPException(404, "文件未找到或已被删除")

@app.get("/api/files/download-folder/{employee_id}")
def download_employee_folder(employee_id: str, user=Depends(get_user)):
    """打包下载某员工的所有文件（ZIP格式）"""
    import zipfile, io
    if not _can_access_employee_files(user, employee_id):
        raise HTTPException(403, "无权下载该员工文件")
    db = database.get_db()
    try:
        files = db.execute("SELECT * FROM employee_files WHERE employee_id=?", (employee_id,)).fetchall()
        emp = db.execute("SELECT name FROM employees WHERE id=?", (employee_id,)).fetchone()
    finally:
        db.close()
    if not files:
        raise HTTPException(404, "该员工没有文件")
    emp_name = dict(emp)["name"] if emp else employee_id
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for f in files:
            f = dict(f)
            file_url = f.get("file_url") or ""
            if file_url.startswith("/uploads/"):
                file_path = os.path.join(UPLOAD_DIR, file_url.replace("/uploads/", "", 1))
                if os.path.isfile(file_path):
                    arcname = f.get("file_name") or os.path.basename(file_path)
                    zf.write(file_path, arcname)
    buf.seek(0)
    zip_bytes = buf.getvalue()
    from fastapi.responses import Response
    filename = f"{emp_name}_{employee_id}_files.zip"
    return Response(content=zip_bytes, media_type="application/zip",
                    headers={"Content-Disposition": f'attachment; filename="{filename}"'})

# ── Leave ──
@app.get("/api/leave-types")
def get_lt(user=Depends(get_user)): return q("leave_types", order="code ASC")

@app.get("/api/leave-balances")
def get_lb(employee_id: Optional[str] = None, user=Depends(get_user)):
    if employee_id: return q("leave_balances", "employee_id=?", (employee_id,))
    return q("leave_balances", order="employee_id ASC")

@app.get("/api/leave-requests")
def get_lr(user=Depends(get_user)):
    """获取请假申请 - 根据职级、部门、仓库做权限过滤"""
    role = user.get("role", "worker")
    if role == "sup" and user.get("supplier_id"):
        return q("leave_requests", "employee_id IN (SELECT id FROM employees WHERE supplier_id=?)",
                 (user["supplier_id"],))
    emp_ids, scope = _get_scoped_employee_ids(user)
    if scope == "all":
        return q("leave_requests")
    if emp_ids is not None and len(emp_ids) == 0:
        return []
    if emp_ids is not None:
        placeholders = ",".join(["?"] * len(emp_ids))
        return q("leave_requests", f"employee_id IN ({placeholders})", tuple(emp_ids))
    return q("leave_requests")

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
            try:
                db.execute("UPDATE leave_balances SET used_days=used_days+?,remaining_days=remaining_days-? WHERE employee_id=? AND year=? AND leave_type=?",
                    (lr[0]["days"], lr[0]["days"], lr[0]["employee_id"], current_year, lr[0]["leave_type"]))
                db.commit()
            finally:
                db.close()
    audit_log(user.get("username", ""), "update", "leave_requests", lid, json.dumps(list(data.keys())))
    return {"ok": True}

# ── Expenses ──
@app.get("/api/expenses")
def get_expenses(user=Depends(get_user)):
    """获取报销申请 - 根据职级、部门、仓库做权限过滤"""
    role = user.get("role", "worker")
    if role == "sup" and user.get("supplier_id"):
        return q("expense_claims", "employee_id IN (SELECT id FROM employees WHERE supplier_id=?)",
                 (user["supplier_id"],))
    emp_ids, scope = _get_scoped_employee_ids(user)
    if scope == "all":
        return q("expense_claims")
    if emp_ids is not None and len(emp_ids) == 0:
        return []
    if emp_ids is not None:
        placeholders = ",".join(["?"] * len(emp_ids))
        return q("expense_claims", f"employee_id IN ({placeholders})", tuple(emp_ids))
    return q("expense_claims")

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
    # Worker/mgr/operational roles with employee_id: apply grade-based data scope
    operational_roles = ("worker", "mgr", "team_leader", "shift_leader", "deputy_mgr",
                         "site_mgr", "regional_mgr", "ops_director")
    if role in operational_roles and user.get("employee_id"):
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
    try:
        # Supplier users only see their own settlement data
        if role == "sup" and user.get("supplier_id"):
            sid = user["supplier_id"]
            rows = db.execute("SELECT supplier_id,warehouse_code,COUNT(DISTINCT employee_id) hc,SUM(hours) h,SUM(hourly_pay) pay FROM timesheet WHERE supplier_id=? GROUP BY warehouse_code", (sid,)).fetchall()
            return [dict(r) for r in rows]
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
        return [dict(r) for r in rows]
    finally:
        db.close()

# ── Dashboard ──
@app.get("/api/analytics/dashboard")
def dashboard(user=Depends(get_user)):
    db = database.get_db()
    try:
        current_year_month = get_current_year_month()
        role = user.get("role", "worker")

        # Supplier-scoped dashboard: only show their workers' data
        if role == "sup" and user.get("supplier_id"):
            sid = user["supplier_id"]
            # Combine employee counts into a single query instead of duplicate COUNT queries
            emp_stats = db.execute(
                "SELECT COUNT(*) total, COUNT(DISTINCT primary_wh) wh_count FROM employees WHERE status='在职' AND supplier_id=?",
                (sid,)
            ).fetchone()
            r = {
                "total_emp": emp_stats[0],
                "own": 0,
                "supplier": emp_stats[0],
                "wh_count": emp_stats[1],
                "pending_leave": db.execute("SELECT COUNT(*) FROM leave_requests lr JOIN employees e ON lr.employee_id=e.id WHERE lr.status='待审批' AND e.supplier_id=?", (sid,)).fetchone()[0],
                "pending_expense": 0,
                "pending_ts": db.execute("SELECT COUNT(*) FROM timesheet WHERE supplier_id=? AND wh_status='待仓库审批'", (sid,)).fetchone()[0],
                "monthly_hrs": db.execute("SELECT COALESCE(SUM(hours),0) FROM timesheet WHERE supplier_id=? AND work_date LIKE ?", (sid, f"{current_year_month}%")).fetchone()[0],
                "grade_dist": [dict(r) for r in db.execute("SELECT grade,COUNT(*) c FROM employees WHERE status='在职' AND supplier_id=? GROUP BY grade ORDER BY grade", (sid,)).fetchall()],
                "wh_dist": [dict(r) for r in db.execute("SELECT primary_wh w,COUNT(*) c FROM employees WHERE status='在职' AND supplier_id=? GROUP BY primary_wh", (sid,)).fetchall()],
                "service_type_dist": [],
                "dispatch_type_dist": [dict(r) for r in db.execute("SELECT dispatch_type, COUNT(*) c FROM employees WHERE status='在职' AND supplier_id=? AND dispatch_type IS NOT NULL GROUP BY dispatch_type", (sid,)).fetchall()],
            }
            return r

        # Warehouse-scoped dashboard: applies to wh role and other warehouse-scoped roles
        scope = _check_grade_data_scope(user)
        wh = user.get("warehouse_code") or _get_employee_warehouse(user)
        if scope == "own_warehouse" and wh:
            # Combine total/own/supplier employee counts into a single query
            src_counts = db.execute(
                "SELECT source, COUNT(*) c FROM employees WHERE status='在职' AND (primary_wh=? OR dispatch_whs LIKE ?) GROUP BY source",
                (wh, f"%{wh}%")
            ).fetchall()
            src_map = {row["source"]: row["c"] for row in src_counts}
            total_emp = sum(src_map.values())
            r = {
                "total_emp": total_emp,
                "own": src_map.get("自有", 0),
                "supplier": src_map.get("供应商", 0),
                "wh_count": 1,
                "pending_leave": db.execute("SELECT COUNT(*) FROM leave_requests WHERE warehouse_code=? AND status='待审批'", (wh,)).fetchone()[0],
                "pending_expense": 0,
                "pending_ts": db.execute("SELECT COUNT(*) FROM timesheet WHERE warehouse_code=? AND wh_status='待仓库审批'", (wh,)).fetchone()[0],
                "monthly_hrs": db.execute("SELECT COALESCE(SUM(hours),0) FROM timesheet WHERE warehouse_code=? AND work_date LIKE ?", (wh, f"{current_year_month}%")).fetchone()[0],
                "grade_dist": [dict(r) for r in db.execute("SELECT grade,COUNT(*) c FROM employees WHERE status='在职' AND (primary_wh=? OR dispatch_whs LIKE ?) GROUP BY grade ORDER BY grade", (wh, f"%{wh}%")).fetchall()],
                "wh_dist": [{"w": wh, "c": total_emp}],
                "service_type_dist": [],
                "dispatch_type_dist": [dict(r) for r in db.execute("SELECT dispatch_type, COUNT(*) c FROM employees WHERE status='在职' AND (primary_wh=? OR dispatch_whs LIKE ?) AND dispatch_type IS NOT NULL GROUP BY dispatch_type", (wh, f"%{wh}%")).fetchall()],
            }
            return r

        # Global dashboard: combine employee counts into a single query
        src_counts = db.execute(
            "SELECT source, COUNT(*) c FROM employees WHERE status='在职' GROUP BY source"
        ).fetchall()
        src_map = {row["source"]: row["c"] for row in src_counts}
        total_emp = sum(src_map.values())
        r = {
            "total_emp": total_emp,
            "own": src_map.get("自有", 0),
            "supplier": src_map.get("供应商", 0),
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
        return r
    finally:
        db.close()

# ── Permissions ──
# Role hierarchy: admin (god view) > ceo > mgr > hr > fin > wh > sup > worker
ROLE_HIERARCHY = {
    "admin": 100,  # God view - highest permission level
    "ceo": 90,     # CEO level - 王博 and 袁梁毅
    "ops_director": 85,  # 运营总监 - Operations Director (P9)
    "regional_mgr": 80,  # 区域经理 - Regional Manager (P8)
    "site_mgr": 75,      # 驻仓经理 - Site Manager (P7)
    "mgr": 70,     # Manager (legacy general)
    "deputy_mgr": 70,    # 副经理 - Deputy Manager (P6)
    "shift_leader": 65,  # 班组长 - Shift Leader (P5)
    "hr": 60,      # HR (legacy)
    "hr_manager": 60,    # 人事经理 - HR Manager
    "team_leader": 60,   # 组长 - Team Leader (P4)
    "fin_director": 55,  # 财务总监 - Finance Director
    "fin": 50,     # Finance (legacy)
    "hr_assistant": 45,  # 人事助理 - HR Assistant
    "fin_assistant": 45, # 财务助理 - Finance Assistant
    "wh": 40,      # Warehouse (legacy)
    "hr_specialist": 40, # 人事专员 - HR Specialist
    "fin_specialist": 40,# 财务专员 - Finance Specialist
    "admin_assistant": 40,  # 行政助理 - Admin Assistant
    "admin_specialist": 35, # 行政专员 - Admin Specialist
    "sup": 30,     # Supplier
    "worker": 10,  # Worker
    "client": 5,   # Client (customer)
    "jobseeker": 5, # Job seeker
}

# Role sets for access control — derived from organizational hierarchy
# Roles with full data access (bypasses grade-based scope)
FULL_ACCESS_ROLES = frozenset({
    "admin", "ceo", "ops_director",
    "hr", "hr_manager", "hr_assistant", "hr_specialist",
    "fin", "fin_director", "fin_assistant", "fin_specialist",
    "admin_assistant", "admin_specialist"
})
# Roles that can submit dispatch (personnel) requests directly
DISPATCH_REQUEST_ROLES = frozenset({
    "admin", "ceo", "hr", "mgr", "ops_director", "regional_mgr", "site_mgr",
    "deputy_mgr", "shift_leader", "hr_manager"
})
# Roles that can submit transfer (调仓) requests
TRANSFER_REQUEST_ROLES = frozenset({
    "admin", "ceo", "hr", "ops_director", "hr_manager", "site_mgr"
})
# Roles that can view all dispatch transfers
TRANSFER_VIEW_ALL_ROLES = frozenset({
    "admin", "ceo", "hr", "ops_director", "hr_manager", "hr_assistant", "hr_specialist"
})
# Roles that can manage regions
REGION_MANAGE_ROLES = frozenset({"admin", "ceo", "mgr", "ops_director"})

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

def _get_employee_department(user: dict) -> str:
    """Get the department of the employee associated with a user."""
    eid = user.get("employee_id")
    if not eid:
        return ""
    db = database.get_db()
    try:
        emp = db.execute("SELECT department FROM employees WHERE id=?", (eid,)).fetchone()
        return emp["department"] if emp and emp["department"] else ""
    finally:
        db.close()

def _get_scoped_employee_ids(user: dict) -> tuple:
    """Get employee IDs visible to the current user based on grade+department+warehouse scope.
    Returns (list_of_employee_ids, scope_type) where scope_type helps callers decide filtering.
    根据职级、部门、仓库做权限过滤"""
    role = user.get("role", "worker")
    scope = _check_grade_data_scope(user)
    if scope == "all":
        return None, "all"
    if scope == "own_supplier" and user.get("supplier_id"):
        return None, "own_supplier"  # caller should filter by supplier_id
    if scope == "self_only":
        eid = user.get("employee_id", "")
        return [eid] if eid else [], "self_only"
    # For own_warehouse and regional: get employees by warehouse, further filter by department for non-mgr roles
    wh = _get_employee_warehouse(user)
    if scope == "regional":
        region_whs = _get_region_warehouses(wh) if wh else []
        if not region_whs:
            eid = user.get("employee_id", "")
            return [eid] if eid else [], "self_only"
        db = database.get_db()
        try:
            placeholders = ",".join(["?"] * len(region_whs))
            rows = db.execute(f"SELECT id FROM employees WHERE primary_wh IN ({placeholders})",
                              tuple(region_whs)).fetchall()
            return [r["id"] for r in rows], "regional"
        finally:
            db.close()
    # own_warehouse scope: filter by warehouse + department
    if not wh:
        eid = user.get("employee_id", "")
        return [eid] if eid else [], "self_only"
    dept = _get_employee_department(user)
    db = database.get_db()
    try:
        if dept and role in ("team_leader", "shift_leader", "worker"):
            # 部门权限: Team leaders and below see only their own department within the warehouse
            rows = db.execute("SELECT id FROM employees WHERE primary_wh=? AND department=?",
                              (wh, dept)).fetchall()
        else:
            rows = db.execute("SELECT id FROM employees WHERE primary_wh=?", (wh,)).fetchall()
        return [r["id"] for r in rows], "own_warehouse"
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

def _check_grade_data_scope(user: dict) -> str:
    """Determine data access scope based on employee grade.
    Returns: 'all', 'regional', 'own_warehouse', 'self_only', 'own_supplier'.
    For roles admin/ceo/ops_director/hr/hr_manager/fin/fin_director and other full-access roles,
    always returns 'all' (bypasses grade check).
    For operational roles, uses grade-based scope if employee_id is linked.
    When no employee/grade is linked, falls back to the role's configured data_scope
    from permission_overrides instead of defaulting to 'self_only'."""
    role = user.get("role", "worker")
    if role in FULL_ACCESS_ROLES:
        return "all"
    if role == "regional_mgr":
        return "regional"
    if role in ("site_mgr", "deputy_mgr", "shift_leader", "team_leader", "wh"):
        grade = _get_employee_grade(user)
        if grade:
            gp = _get_grade_permissions(grade)
            return gp["data_scope"]
        return "own_warehouse"
    if role == "sup":
        return "own_supplier"
    grade = _get_employee_grade(user)
    if not grade:
        # No linked employee — use the role's configured data_scope from permission_overrides
        # so that roles like 'mgr' (data_scope='all') don't fall to 'self_only'
        db = database.get_db()
        try:
            perm = db.execute(
                "SELECT data_scope FROM permission_overrides WHERE role=? LIMIT 1", (role,)
            ).fetchone()
            if perm and perm["data_scope"]:
                return perm["data_scope"]
        finally:
            db.close()
        return "self_only"
    gp = _get_grade_permissions(grade)
    return gp["data_scope"]

def _get_role_level(role: str) -> int:
    """Get numeric role level for hierarchy comparison"""
    return ROLE_HIERARCHY.get(role, 0)

@app.get("/api/permissions")
def get_perms(user=Depends(get_user)): return q("permission_overrides", order="role ASC, module ASC", limit=1000)

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
    """Get all regions with their warehouses and managers."""
    db = database.get_db()
    try:
        regions = db.execute("SELECT * FROM regions ORDER BY code").fetchall()
        regions = [dict(r) for r in regions]
        # Collect all warehouse codes across all regions in one pass
        all_wh_codes = set()
        for reg in regions:
            wh_codes = [c.strip() for c in (reg.get("warehouse_codes") or "").split(",") if c.strip()]
            all_wh_codes.update(wh_codes)
        # Batch-fetch all warehouses at once instead of per-region queries
        wh_map = {}
        if all_wh_codes:
            placeholders = ",".join(["?"] * len(all_wh_codes))
            wh_rows = db.execute(
                f"SELECT code, name, address, manager, current_headcount FROM warehouses WHERE code IN ({placeholders})",
                list(all_wh_codes)
            ).fetchall()
            wh_map = {r["code"]: dict(r) for r in wh_rows}
        # Enrich each region with cached warehouse details
        for reg in regions:
            wh_codes = [c.strip() for c in (reg.get("warehouse_codes") or "").split(",") if c.strip()]
            reg["warehouses"] = [wh_map[wc] for wc in wh_codes if wc in wh_map]
        return regions
    finally:
        db.close()

@app.post("/api/regions")
async def create_region(request: Request, user=Depends(get_user)):
    """Create a new region. Admin/CEO/MGR/Ops Director only."""
    if user.get("role") not in REGION_MANAGE_ROLES:
        raise HTTPException(403, "无权创建大区 / No permission to create region")
    data = await request.json()
    if not data.get("code") or not data.get("name"):
        raise HTTPException(400, "大区编码和名称不能为空 / Region code and name required")
    data.setdefault("created_at", datetime.now().isoformat())
    data.setdefault("updated_at", datetime.now().isoformat())
    data.setdefault("status", "启用")
    try:
        insert("regions", data)
    except Exception as e:
        raise HTTPException(500, f"创建大区失败: {str(e)}")
    # Update warehouse region fields (batch update with IN clause)
    wh_codes = [c.strip() for c in (data.get("warehouse_codes") or "").split(",") if c.strip()]
    if wh_codes:
        db = database.get_db()
        try:
            now = datetime.now().isoformat()
            placeholders = ",".join(["?"] * len(wh_codes))
            db.execute(f"UPDATE warehouses SET region=?, updated_at=? WHERE code IN ({placeholders})",
                       [data["name"], now] + wh_codes)
            db.commit()
        finally:
            db.close()
    audit_log(user.get("username", ""), "create", "regions", data["code"], f"创建大区: {data.get('name','')}")
    return {"ok": True, "code": data["code"]}

@app.put("/api/regions/{code}")
async def update_region(code: str, request: Request, user=Depends(get_user)):
    """Update a region. Admin/CEO/MGR/Ops Director only."""
    if user.get("role") not in REGION_MANAGE_ROLES:
        raise HTTPException(403, "无权修改大区 / No permission to update region")
    data = await request.json()
    data.pop("code", None)
    data["updated_at"] = datetime.now().isoformat()
    # Get old region to clear warehouse region fields
    db = database.get_db()
    try:
        old = db.execute("SELECT * FROM regions WHERE code=?", (code,)).fetchone()
        if not old:
            raise HTTPException(404, "大区不存在 / Region not found")
        old_wh_codes = [c.strip() for c in (old["warehouse_codes"] or "").split(",") if c.strip()]
        # Clear old warehouse region fields (batch update with IN clause)
        if old_wh_codes:
            now_ts = datetime.now().isoformat()
            placeholders = ",".join(["?"] * len(old_wh_codes))
            db.execute(f"UPDATE warehouses SET region='', updated_at=? WHERE code IN ({placeholders})",
                       [now_ts] + old_wh_codes)
        # Update region record
        sets = ",".join(f"{k}=?" for k in data.keys())
        db.execute(f"UPDATE regions SET {sets} WHERE code=?", list(data.values()) + [code])
        # Set new warehouse region fields only if warehouse_codes was provided or unchanged
        if "warehouse_codes" in data:
            new_wh_codes = [c.strip() for c in (data["warehouse_codes"] or "").split(",") if c.strip()]
        else:
            new_wh_codes = old_wh_codes
        region_name = data.get("name", old["name"])
        if new_wh_codes:
            now_ts = datetime.now().isoformat()
            placeholders = ",".join(["?"] * len(new_wh_codes))
            db.execute(f"UPDATE warehouses SET region=?, updated_at=? WHERE code IN ({placeholders})",
                       [region_name, now_ts] + new_wh_codes)
        db.commit()
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, f"更新大区失败: {str(e)}")
    finally:
        db.close()
    audit_log(user.get("username", ""), "update", "regions", code, json.dumps(list(data.keys())))
    return {"ok": True}

@app.delete("/api/regions/{code}")
def delete_region(code: str, user=Depends(get_user)):
    """Delete a region. Admin only."""
    if user.get("role") not in ("admin", "ceo"):
        raise HTTPException(403, "无权删除大区 / No permission to delete region")
    db = database.get_db()
    try:
        old = db.execute("SELECT * FROM regions WHERE code=?", (code,)).fetchone()
        if not old:
            raise HTTPException(404, "大区不存在 / Region not found")
        # Clear warehouse region fields (batch update with IN clause)
        wh_codes = [c.strip() for c in (old["warehouse_codes"] or "").split(",") if c.strip()]
        if wh_codes:
            now_ts = datetime.now().isoformat()
            placeholders = ",".join(["?"] * len(wh_codes))
            db.execute(f"UPDATE warehouses SET region='', updated_at=? WHERE code IN ({placeholders})",
                       [now_ts] + wh_codes)
        db.execute("DELETE FROM regions WHERE code=?", (code,))
        db.commit()
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, f"删除大区失败: {str(e)}")
    finally:
        db.close()
    audit_log(user.get("username", ""), "delete", "regions", code, f"删除大区: {old['name']}")
    return {"ok": True}

@app.get("/api/regions/permissions")
def get_region_manager_permissions(user=Depends(get_user)):
    """Get regional manager (P8) permission details for display."""
    grade_perms = GRADE_PERMISSIONS.get("P8", {})
    return {
        "grade": "P8",
        "title": "区域经理 / Regional Manager",
        "data_scope": grade_perms.get("data_scope", "regional"),
        "salary_scope": grade_perms.get("salary_scope", "regional"),
        "can_dispatch_request": grade_perms.get("can_dispatch_request", True),
        "can_transfer_request": grade_perms.get("can_transfer_request", True),
        "permissions_detail": [
            {"module": "工时记录", "scope": "可查看和审批所辖大区所有仓库的工时记录"},
            {"module": "排班管理", "scope": "可查看和管理所辖大区所有仓库的排班"},
            {"module": "薪资配置", "scope": "可配置和修改所辖大区仓库的薪资标准"},
            {"module": "派遣需求", "scope": "可提交和审批所辖大区的派遣需求"},
            {"module": "人员调配", "scope": "可发起和审批所辖大区内的人员调配"},
            {"module": "安全管理", "scope": "可查看和处理所辖大区的安全事件"},
            {"module": "报价管理", "scope": "可管理所辖大区客户的报价"},
        ],
        "approval_flow": "工时审批流程: 班组长 → 驻仓经理 → 区域经理 → 财务总监",
    }

@app.post("/api/permissions/update")
async def update_perm(request: Request, user=Depends(get_user)):
    d = await request.json()
    if not d.get("role") or not d.get("module"):
        raise HTTPException(400, "角色和模块不能为空")
    # Only admin can update permissions
    if user.get("role") != "admin":
        raise HTTPException(403, "仅管理员可修改权限设置")
    db = database.get_db()
    try:
        db.execute("""UPDATE permission_overrides SET can_view=?,can_create=?,can_edit=?,can_delete=?,
            can_export=?,can_approve=?,can_import=?,hidden_fields=?,editable_fields=?,
            data_scope=?,scope_grades=?,scope_departments=?,scope_warehouses=? WHERE role=? AND module=?""",
            (d.get("can_view",0),d.get("can_create",0),d.get("can_edit",0),d.get("can_delete",0),
             d.get("can_export",0),d.get("can_approve",0),d.get("can_import",0),
             d.get("hidden_fields",""),d.get("editable_fields",""),
             d.get("data_scope","all"),d.get("scope_grades",""),d.get("scope_departments",""),d.get("scope_warehouses",""),
             d["role"],d["module"]))
        db.commit()
    finally:
        db.close()
    audit_log(user.get("username", ""), "update", "permission_overrides", f"{d['role']}/{d['module']}", json.dumps(d))
    return {"ok": True}

@app.get("/api/roles")
def get_roles(user=Depends(get_user)):
    """Get all available roles with hierarchy levels"""
    return [
        {"role": "admin", "label": "系统管理员", "level": 100, "description": "上帝视角 - 最高权限"},
        {"role": "ceo", "label": "老板/CEO", "level": 90, "description": "公司最高管理层 (王博/袁梁毅)"},
        {"role": "ops_director", "label": "运营总监", "level": 85, "description": "对所有仓有修改权 (P9)"},
        {"role": "regional_mgr", "label": "区域经理", "level": 80, "description": "对其区域管辖仓库有修改权，薪资/报价有范围权限 (P8)"},
        {"role": "site_mgr", "label": "驻仓经理", "level": 75, "description": "对其负责仓库有修改权，薪资/报价有范围限制 (P7)"},
        {"role": "deputy_mgr", "label": "副经理", "level": 70, "description": "整仓代管，协助驻仓经理 (P6)"},
        {"role": "shift_leader", "label": "班组长", "level": 65, "description": "独立负责整班次，可提交人员需求 (P5)"},
        {"role": "team_leader", "label": "组长", "level": 60, "description": "带班3-10人，本仓数据权限，薪资仅建议权 (P4)"},
        {"role": "hr_manager", "label": "人事经理", "level": 60, "description": "人力资源管理负责人"},
        {"role": "fin_director", "label": "财务总监", "level": 55, "description": "公司财务最高负责人"},
        {"role": "hr_assistant", "label": "人事助理", "level": 45, "description": "协助人事工作"},
        {"role": "fin_assistant", "label": "财务助理", "level": 45, "description": "协助财务工作"},
        {"role": "hr_specialist", "label": "人事专员", "level": 40, "description": "独立人事流程"},
        {"role": "fin_specialist", "label": "财务专员", "level": 40, "description": "独立财务流程"},
        {"role": "admin_assistant", "label": "行政助理", "level": 40, "description": "日常行政工作"},
        {"role": "admin_specialist", "label": "行政专员", "level": 35, "description": "独立行政流程"},
        {"role": "mgr", "label": "经理", "level": 70, "description": "部门/区域经理 (通用)"},
        {"role": "hr", "label": "人事", "level": 60, "description": "人力资源管理 (通用)"},
        {"role": "fin", "label": "财务", "level": 50, "description": "财务管理 (通用)"},
        {"role": "wh", "label": "仓库", "level": 40, "description": "仓库管理 (通用)"},
        {"role": "sup", "label": "供应商", "level": 30, "description": "供应商账号"},
        {"role": "worker", "label": "员工/工人", "level": 10, "description": "一线工人 (P0-P3)"},
        {"role": "client", "label": "客户", "level": 5, "description": "客户账号 - 仅查看报价和账单"},
        {"role": "jobseeker", "label": "求职者", "level": 5, "description": "求职者 - 查看招聘需求和上传文件"},
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

# ── Job Positions (岗位定义 - 可自行设定，关联到花名册) ──

@app.get("/api/job-positions")
def get_job_positions(user=Depends(get_user)):
    """Get all job positions. Returns list of defined positions linked to grade levels and roles."""
    return q("job_positions", order="level DESC, code ASC")

@app.get("/api/job-positions/{code}")
def get_job_position(code: str, user=Depends(get_user)):
    """Get a specific job position by code."""
    db = database.get_db()
    try:
        row = db.execute("SELECT * FROM job_positions WHERE code=?", (code,)).fetchone()
        if not row:
            raise HTTPException(404, "岗位不存在 / Position not found")
        return dict(row)
    finally:
        db.close()

@app.post("/api/job-positions")
async def create_job_position(request: Request, user=Depends(get_user)):
    """Create a new job position. Admin only."""
    if user.get("role") != "admin":
        raise HTTPException(403, "仅管理员可创建岗位 / Only admin can create positions")
    data = await request.json()
    if not data.get("code") or not data.get("title_zh"):
        raise HTTPException(400, "岗位编码和中文名称不能为空 / Position code and Chinese title required")
    data.setdefault("status", "启用")
    data.setdefault("created_at", datetime.now().isoformat())
    data.setdefault("updated_at", datetime.now().isoformat())
    try:
        insert("job_positions", data)
    except Exception as e:
        raise HTTPException(500, f"创建岗位失败: {str(e)}")
    audit_log(user.get("username", ""), "create", "job_positions", data["code"], f"创建岗位: {data.get('title_zh','')}")
    return {"ok": True, "code": data["code"]}

@app.put("/api/job-positions/{code}")
async def update_job_position(code: str, request: Request, user=Depends(get_user)):
    """Update a job position. Admin only."""
    if user.get("role") != "admin":
        raise HTTPException(403, "仅管理员可修改岗位 / Only admin can update positions")
    data = await request.json()
    data.pop("code", None)
    data["updated_at"] = datetime.now().isoformat()
    db = database.get_db()
    try:
        old = db.execute("SELECT * FROM job_positions WHERE code=?", (code,)).fetchone()
        if not old:
            raise HTTPException(404, "岗位不存在 / Position not found")
        sets = ",".join(f"{k}=?" for k in data.keys())
        db.execute(f"UPDATE job_positions SET {sets} WHERE code=?", list(data.values()) + [code])
        db.commit()
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, f"更新岗位失败: {str(e)}")
    finally:
        db.close()
    audit_log(user.get("username", ""), "update", "job_positions", code, json.dumps(list(data.keys())))
    return {"ok": True}

@app.delete("/api/job-positions/{code}")
def delete_job_position(code: str, user=Depends(get_user)):
    """Delete a job position. Admin only."""
    if user.get("role") != "admin":
        raise HTTPException(403, "仅管理员可删除岗位 / Only admin can delete positions")
    db = database.get_db()
    try:
        old = db.execute("SELECT * FROM job_positions WHERE code=?", (code,)).fetchone()
        if not old:
            raise HTTPException(404, "岗位不存在 / Position not found")
        db.execute("DELETE FROM job_positions WHERE code=?", (code,))
        db.commit()
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, f"删除岗位失败: {str(e)}")
    finally:
        db.close()
    audit_log(user.get("username", ""), "delete", "job_positions", code, f"删除岗位: {old['title_zh']}")
    return {"ok": True}

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
                   "id_expiry_date","address","source","supplier_id","biz_line","department","primary_wh","dispatch_whs",
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
                   "birth_date":"出生日期","id_type":"证件类型","id_number":"证件号码","id_expiry_date":"证件有效期",
                   "address":"地址",
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
        try:
            perm = db.execute("SELECT hidden_fields FROM permission_overrides WHERE role=? AND module=?",
                              (role, module)).fetchone()
        finally:
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

@app.post("/api/import-file/{table}")
async def import_file_table(table: str, file: UploadFile = File(...), user=Depends(get_user)):
    """批量导入：支持CSV和Excel文件上传导入。
    CSV文件需要UTF-8编码，表头使用中文标签或英文字段名。
    Excel文件需要.xlsx格式。"""
    import csv, io
    if table not in TABLE_EXPORT_FIELDS:
        raise HTTPException(400, f"不支持导入的表: {table}")
    module = MODULE_MAP.get(table, table)
    if not _check_permission(user, module, "can_import"):
        raise HTTPException(403, "无导入权限")

    content = await file.read()
    filename = file.filename or ""
    ext = os.path.splitext(filename)[1].lower()

    fields = TABLE_EXPORT_FIELDS[table]
    labels = TABLE_FIELD_LABELS.get(table, {})
    # Build reverse label map (Chinese label -> field name)
    label_to_field = {}
    for f in fields:
        label_to_field[f] = f
        if f in labels:
            label_to_field[labels[f]] = f

    records = []
    if ext in (".csv", ".tsv", ".txt"):
        # Try to decode as UTF-8 with BOM, fallback to utf-8
        try:
            text = content.decode("utf-8-sig")
        except UnicodeDecodeError:
            text = content.decode("utf-8", errors="replace")
        reader = csv.DictReader(io.StringIO(text))
        for row in reader:
            record = {}
            for header, value in row.items():
                if header is None:
                    continue
                field = label_to_field.get(header.strip(), header.strip())
                if field in fields:
                    record[field] = value.strip() if value else ""
            if record:
                records.append(record)
    elif ext in (".xlsx", ".xls"):
        try:
            import openpyxl
        except ImportError:
            raise HTTPException(400, "服务器未安装openpyxl，请使用CSV格式导入")
        wb = openpyxl.load_workbook(io.BytesIO(content), read_only=True)
        ws = wb.active
        rows_iter = ws.iter_rows(values_only=True)
        header_row = next(rows_iter, None)
        if not header_row:
            raise HTTPException(400, "Excel文件为空")
        # Map headers to field names
        col_map = []
        for h in header_row:
            h_str = str(h).strip() if h else ""
            col_map.append(label_to_field.get(h_str, h_str))
        for row in rows_iter:
            record = {}
            for i, value in enumerate(row):
                if i < len(col_map) and col_map[i] in fields:
                    record[col_map[i]] = str(value).strip() if value is not None else ""
            if record and any(v for v in record.values()):
                records.append(record)
        wb.close()
    else:
        raise HTTPException(400, "不支持的文件格式，请使用CSV(.csv)或Excel(.xlsx)文件")

    if not records:
        raise HTTPException(400, "文件中没有有效数据")

    # Reuse the same import logic as JSON import
    id_col = "code" if table == "warehouses" else "id"
    success = 0
    errors = []
    db = database.get_db()
    try:
        for i, record in enumerate(records):
            try:
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
                _tables_with_updated_at = {"employees", "suppliers", "timesheet", "warehouses",
                                           "leave_requests", "expense_claims", "performance_reviews"}
                if table in _tables_with_updated_at:
                    record.setdefault("updated_at", now)
                if table == "employees" and not record.get("name"):
                    errors.append({"row": i, "error": "员工姓名不能为空"})
                    continue
                if table == "suppliers" and not record.get("name"):
                    errors.append({"row": i, "error": "供应商名称不能为空"})
                    continue
                existing = db.execute(f"SELECT {id_col} FROM {table} WHERE {id_col}=?",
                                      (record[id_col],)).fetchone()
                if existing:
                    update_data = {k: v for k, v in record.items() if k != id_col}
                    if table in _tables_with_updated_at:
                        update_data["updated_at"] = now
                    sets = ",".join(f"{k}=?" for k in update_data.keys())
                    db.execute(f"UPDATE {table} SET {sets} WHERE {id_col}=?",
                               list(update_data.values()) + [record[id_col]])
                else:
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
    audit_log(user.get("username", ""), "import_file", table, f"batch_{success}",
              f"文件导入{success}条, 失败{len(errors)}条, 来源: {filename}")
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

@app.post("/api/recruit")
async def create_recruit(request: Request, user=Depends(get_user)):
    data = await request.json()
    data["id"] = f"RP-{uuid.uuid4().hex[:6]}"
    data.setdefault("created_at", datetime.now().isoformat())
    try:
        insert("recruit_progress", data)
    except Exception as e:
        raise HTTPException(500, f"创建招聘记录失败: {str(e)}")
    audit_log(user.get("username", ""), "create", "recruit_progress", data["id"], f"候选人: {data.get('candidate_id','')}")
    return {"ok": True, "id": data["id"]}

@app.put("/api/recruit/{rid}")
async def update_recruit(rid: str, request: Request, user=Depends(get_user)):
    data = await request.json()
    try:
        update("recruit_progress", "id", rid, data)
    except Exception as e:
        raise HTTPException(500, f"更新招聘记录失败: {str(e)}")
    audit_log(user.get("username", ""), "update", "recruit_progress", rid, json.dumps(list(data.keys())))
    return {"ok": True}

@app.post("/api/dispatch")
async def create_dispatch(request: Request, user=Depends(get_user)):
    data = await request.json()
    if not data.get("warehouse_code"):
        raise HTTPException(400, "仓库编码不能为空")
    # Grade-based check: P5+ can submit personnel requests, or roles in DISPATCH_REQUEST_ROLES
    role = user.get("role", "worker")
    if role not in DISPATCH_REQUEST_ROLES:
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
    if role in TRANSFER_VIEW_ALL_ROLES:
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
    """创建人员调仓申请 - P7及以上或admin/ceo/hr/ops_director/site_mgr可发起"""
    role = user.get("role", "worker")
    # Grade-based check: P7+ can submit transfer requests, or roles in TRANSFER_REQUEST_ROLES
    if role not in TRANSFER_REQUEST_ROLES:
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

# ── Cloud Sync Configs (WPS 多维表格 / 腾讯文档) ──

@app.get("/api/cloud-sync-configs")
def list_cloud_sync_configs(user=Depends(get_user)):
    if user.get("role") not in ("admin", "hr", "mgr", "fin"):
        raise HTTPException(403, "无权限查看云文档配置")
    rows = q("cloud_sync_configs", order="created_at DESC")
    # Mask app_secret for non-admin users
    for r in rows:
        if r.get("app_secret") and user.get("role") != "admin":
            r["app_secret"] = "****"
    return rows

@app.post("/api/cloud-sync-configs")
async def create_cloud_sync_config(request: Request, user=Depends(get_user)):
    if user.get("role") not in ("admin", "hr", "mgr"):
        raise HTTPException(403, "无权限创建云文档配置")
    body = await request.json()
    cid = f"CSC-{uuid.uuid4().hex[:8].upper()}"
    provider = body.get("provider", "wps")
    if provider not in ("wps", "tencent"):
        raise HTTPException(400, "provider 必须为 wps 或 tencent")
    sync_table = body.get("sync_table", "")
    if not sync_table:
        raise HTTPException(400, "sync_table 不能为空")
    data = {
        "id": cid,
        "provider": provider,
        "name": body.get("name", ""),
        "app_id": body.get("app_id", ""),
        "app_secret": body.get("app_secret", ""),
        "table_id": body.get("table_id", ""),
        "doc_id": body.get("doc_id", ""),
        "sync_table": sync_table,
        "sync_direction": body.get("sync_direction", "push"),
        "status": body.get("status", "已启用"),
        "created_by": user.get("username", ""),
    }
    insert("cloud_sync_configs", data)
    audit_log(user.get("username", ""), "create", "cloud_sync_configs", cid, json.dumps(data, ensure_ascii=False))
    return {**data, "ok": True}

@app.put("/api/cloud-sync-configs/{config_id}")
async def update_cloud_sync_config(config_id: str, request: Request, user=Depends(get_user)):
    if user.get("role") not in ("admin", "hr", "mgr"):
        raise HTTPException(403, "无权限修改云文档配置")
    body = await request.json()
    allowed = {"name", "app_id", "app_secret", "table_id", "doc_id",
               "sync_table", "sync_direction", "status"}
    data = {k: v for k, v in body.items() if k in allowed}
    if "provider" in body and body["provider"] not in ("wps", "tencent"):
        raise HTTPException(400, "provider 必须为 wps 或 tencent")
    if "provider" in body:
        data["provider"] = body["provider"]
    data["updated_at"] = datetime.now().isoformat()
    update("cloud_sync_configs", "id", config_id, data)
    audit_log(user.get("username", ""), "update", "cloud_sync_configs", config_id, json.dumps(data, ensure_ascii=False))
    return {"ok": True, "id": config_id}

@app.delete("/api/cloud-sync-configs/{config_id}")
def delete_cloud_sync_config(config_id: str, user=Depends(get_user)):
    if user.get("role") not in ("admin", "hr", "mgr"):
        raise HTTPException(403, "无权限删除云文档配置")
    db = database.get_db()
    try:
        db.execute("DELETE FROM cloud_sync_configs WHERE id=?", (config_id,))
        db.commit()
    finally:
        db.close()
    audit_log(user.get("username", ""), "delete", "cloud_sync_configs", config_id, "")
    return {"ok": True}

@app.post("/api/cloud-sync-configs/{config_id}/sync")
def trigger_cloud_sync(config_id: str, user=Depends(get_user)):
    """Trigger a sync operation for the given cloud sync config.
    This generates the data payload and returns it for client-side push to WPS/Tencent."""
    if user.get("role") not in ("admin", "hr", "mgr", "fin"):
        raise HTTPException(403, "无权限执行同步")
    rows = q("cloud_sync_configs", where="id=?", params=(config_id,))
    if not rows:
        raise HTTPException(404, "配置不存在")
    config = rows[0]
    sync_table = config.get("sync_table", "")
    if sync_table not in TABLE_EXPORT_FIELDS:
        raise HTTPException(400, f"不支持同步的表: {sync_table}")

    fields = TABLE_EXPORT_FIELDS[sync_table]
    labels = TABLE_FIELD_LABELS.get(sync_table, {})
    data_rows = q(sync_table)
    export_data = []
    for row in data_rows:
        export_data.append({labels.get(f, f): row.get(f) for f in fields if f in row})

    # Update last_sync_at
    update("cloud_sync_configs", "id", config_id, {
        "last_sync_at": datetime.now().isoformat(),
        "updated_at": datetime.now().isoformat(),
    })
    audit_log(user.get("username", ""), "sync", "cloud_sync_configs", config_id,
              f"synced {len(export_data)} rows from {sync_table}")

    return {
        "ok": True,
        "config": config,
        "table": sync_table,
        "fields": [labels.get(f, f) for f in fields],
        "count": len(export_data),
        "data": export_data,
    }

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
async def upload_file(file: UploadFile = File(...), category: str = Form("general"), user=Depends(get_user)):
    ext = os.path.splitext(file.filename)[1]
    fname = f"{category}_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}{ext}"
    path = os.path.join(UPLOAD_DIR, fname)
    content = await file.read()
    with open(path, "wb") as f: f.write(content)
    audit_log(user.get("username", ""), "upload", "file", fname, f"文件: {file.filename}, 大小: {len(content)}")
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
        generated_by = user.get("display_name", "")
        payslip_data = [
            (str(uuid.uuid4()), r["employee_id"], r["name"], month,
             r["total_hours"], r["hourly_pay"], r["piece_pay"],
             r["perf_bonus"], r["other_bonus"], r["gross_pay"],
             r["ssi_deduct"], r["tax_deduct"], r["net_pay"],
             generated_by)
            for r in rows
        ]
        if payslip_data:
            cursor = db.cursor()
            cursor.executemany("""
                INSERT OR REPLACE INTO payslips
                (id, employee_id, employee_name, month, total_hours, hourly_pay,
                 piece_pay, perf_bonus, other_bonus, gross_pay, ssi_deduct, tax_deduct,
                 other_deduct, net_pay, status, generated_by)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,0,?,'待确认',?)
            """, payslip_data)
        count = len(payslip_data)
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

# ── Database Backup & Restore ──

@app.post("/api/backup")
def create_backup(user=Depends(get_user)):
    """Create a database backup. Admin only."""
    if user.get("role") != "admin":
        raise HTTPException(403, "仅管理员可创建备份")
    try:
        filepath = database.backup_database(tag="manual")
        filename = os.path.basename(filepath)
        audit_log(user.get("username", ""), "backup", "database", filename, "手动创建数据库备份")
        return {"ok": True, "filename": filename, "path": filepath}
    except Exception as e:
        raise HTTPException(500, f"备份失败: {str(e)}")

@app.get("/api/backup/list")
def list_backups(user=Depends(get_user)):
    """List available database backups. Admin only."""
    if user.get("role") != "admin":
        raise HTTPException(403, "仅管理员可查看备份列表")
    return database.list_backups()

@app.post("/api/backup/restore")
async def restore_backup(request: Request, user=Depends(get_user)):
    """Restore database from a backup file. Admin only."""
    if user.get("role") != "admin":
        raise HTTPException(403, "仅管理员可恢复备份")
    data = await request.json()
    filename = data.get("filename")
    if not filename:
        raise HTTPException(400, "请指定备份文件名")
    # Validate filename to prevent path traversal
    safe_filename = os.path.basename(filename)
    if safe_filename != filename or ".." in filename:
        raise HTTPException(400, "无效的文件名")
    try:
        summary = database.restore_database(filename)
        audit_log(user.get("username", ""), "restore", "database", filename,
                  json.dumps(summary, ensure_ascii=False))
        return {"ok": True, "filename": filename, "restored": summary,
                "total_rows": sum(summary.values())}
    except FileNotFoundError as e:
        raise HTTPException(404, str(e))
    except Exception as e:
        raise HTTPException(500, f"恢复失败: {str(e)}")

# ── Static Files & SPA ──
app.mount("/uploads", StaticFiles(directory=UPLOAD_DIR), name="uploads")

@app.get("/{path:path}")
def spa(path: str):
    # 根路径 → 公司介绍首页
    if not path:
        for d in [STATIC_DIR, os.path.dirname(__file__)]:
            hp = os.path.join(d, "home.html")
            if os.path.isfile(hp):
                return FileResponse(hp)

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
