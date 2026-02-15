"""渊博+579 HR V6 Database — All Modules (Enhanced with Warehouse Salary Config)
Database Abstraction Layer supporting both SQLite and PostgreSQL
"""
import os, random, json
from datetime import datetime, timedelta

DB_PATH = os.path.join(os.path.dirname(__file__), "hr_system.db")
DATABASE_URL = os.environ.get("DATABASE_URL", "")

# Determine database type based on DATABASE_URL
USE_POSTGRES = DATABASE_URL.startswith("postgresql://") or DATABASE_URL.startswith("postgres://")

if USE_POSTGRES:
    import psycopg2
    import psycopg2.extras
    import psycopg2.extensions
else:
    import sqlite3


class PgRowWrapper:
    """Wraps PostgreSQL RealDictRow to support both integer and string indexing"""
    def __init__(self, row):
        self._row = row
        self._keys = list(row.keys())

    def __getitem__(self, key):
        if isinstance(key, int):
            return self._row[self._keys[key]]
        return self._row[key]

    def __contains__(self, key):
        return key in self._row

    def __repr__(self):
        return repr(self._row)

    def __len__(self):
        return len(self._row)

    def keys(self):
        return self._row.keys()

    def values(self):
        return self._row.values()

    def items(self):
        return self._row.items()

    def get(self, key, default=None):
        if isinstance(key, int):
            try:
                return self._row[self._keys[key]]
            except IndexError:
                return default
        return self._row.get(key, default)


class CursorWrapper:
    """Wrapper for cursor to handle placeholder conversion and result formatting"""
    def __init__(self, cursor, is_postgres=False):
        self._cursor = cursor
        self._is_postgres = is_postgres
    
    def _convert_placeholders(self, sql):
        """Convert ? placeholders to %s for PostgreSQL, avoiding string literals"""
        if not self._is_postgres or '?' not in sql:
            return sql
        
        # More robust placeholder conversion that avoids string literals
        result = []
        in_single_quote = False
        in_double_quote = False
        i = 0
        
        while i < len(sql):
            char = sql[i]
            
            # Track quote state
            if char == "'" and not in_double_quote:
                in_single_quote = not in_single_quote
                result.append(char)
            elif char == '"' and not in_single_quote:
                in_double_quote = not in_double_quote
                result.append(char)
            # Convert ? to %s only outside of quotes
            elif char == '?' and not in_single_quote and not in_double_quote:
                result.append('%s')
            else:
                result.append(char)
            
            i += 1
        
        return ''.join(result)
    
    def execute(self, sql, params=()):
        """Execute SQL with automatic placeholder conversion"""
        sql = self._convert_placeholders(sql)
        return self._cursor.execute(sql, params)
    
    def executemany(self, sql, params_list):
        """Execute SQL multiple times with automatic placeholder conversion"""
        sql = self._convert_placeholders(sql)
        return self._cursor.executemany(sql, params_list)
    
    def fetchone(self):
        row = self._cursor.fetchone()
        if row is not None and self._is_postgres:
            return PgRowWrapper(row)
        return row
    
    def fetchall(self):
        rows = self._cursor.fetchall()
        if self._is_postgres:
            return [PgRowWrapper(r) for r in rows]
        return rows
    
    def fetchmany(self, size=None):
        if size is None:
            rows = self._cursor.fetchmany()
        else:
            rows = self._cursor.fetchmany(size)
        if self._is_postgres:
            return [PgRowWrapper(r) for r in rows]
        return rows
    
    @property
    def rowcount(self):
        return self._cursor.rowcount
    
    @property
    def lastrowid(self):
        return self._cursor.lastrowid
    
    def __iter__(self):
        return iter(self._cursor)


class DBWrapper:
    """Wrapper for database connection to handle differences between SQLite and PostgreSQL"""
    def __init__(self, conn, is_postgres=False):
        self._conn = conn
        self._is_postgres = is_postgres
    
    def execute(self, sql, params=()):
        """Execute SQL with automatic placeholder conversion"""
        cursor = self.cursor()
        cursor.execute(sql, params)
        return cursor
    
    def cursor(self):
        """Get a cursor wrapper"""
        if self._is_postgres:
            # Use RealDictCursor for PostgreSQL to get dict-like results
            raw_cursor = self._conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        else:
            raw_cursor = self._conn.cursor()
        return CursorWrapper(raw_cursor, self._is_postgres)
    
    def commit(self):
        return self._conn.commit()
    
    def rollback(self):
        return self._conn.rollback()
    
    def close(self):
        return self._conn.close()
    
    @property
    def row_factory(self):
        if hasattr(self._conn, 'row_factory'):
            return self._conn.row_factory
        return None
    
    @row_factory.setter
    def row_factory(self, factory):
        if hasattr(self._conn, 'row_factory'):
            self._conn.row_factory = factory


def get_db():
    """Get database connection with abstraction layer"""
    if USE_POSTGRES:
        conn = psycopg2.connect(DATABASE_URL, connect_timeout=5)
        # Set autocommit to False to match SQLite behavior
        conn.autocommit = False
        return DBWrapper(conn, is_postgres=True)
    else:
        import sqlite3
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return DBWrapper(conn, is_postgres=False)


def _adapt_sql_for_db(sql):
    """Adapt SQL statement for the current database type"""
    if USE_POSTGRES:
        # Convert datetime('now') to CURRENT_TIMESTAMP
        # Replace the longer pattern first to avoid partial replacements
        sql = sql.replace("DEFAULT (datetime('now'))", "DEFAULT CURRENT_TIMESTAMP")
        sql = sql.replace("datetime('now')", "CURRENT_TIMESTAMP")
        
        # Convert INTEGER PRIMARY KEY AUTOINCREMENT to SERIAL PRIMARY KEY
        sql = sql.replace("INTEGER PRIMARY KEY AUTOINCREMENT", "SERIAL PRIMARY KEY")
        
        # Convert TEXT to VARCHAR for timestamp columns (optional, TEXT works in PostgreSQL)
        # Keep TEXT as is since PostgreSQL supports it
        
        return sql
    else:
        return sql

def init_db():
    conn = get_db(); c = conn.cursor()
    tables = [
    # ── Grade Levels P0-P9/M1-M5 ──
    """CREATE TABLE IF NOT EXISTS grade_levels (
        code TEXT PRIMARY KEY, series TEXT NOT NULL, level INTEGER,
        title_zh TEXT, title_en TEXT, title_de TEXT,
        base_salary REAL DEFAULT 0, salary_currency TEXT DEFAULT 'EUR',
        manage_scope TEXT, headcount_range TEXT,
        eval_criteria TEXT, promotion_path TEXT, promotion_conditions TEXT,
        perf_dimensions TEXT, bonus_eligible INTEGER DEFAULT 1,
        adjust_pct_min REAL DEFAULT 0, adjust_pct_max REAL DEFAULT 0,
        description TEXT, created_at TEXT DEFAULT (datetime('now')))""",
    # ── Grade Evaluations ──
    """CREATE TABLE IF NOT EXISTS grade_evaluations (
        id TEXT PRIMARY KEY, employee_id TEXT, current_grade TEXT, target_grade TEXT,
        eval_type TEXT DEFAULT '晋升评定', eval_date TEXT, evaluator TEXT,
        criteria_results TEXT, total_score REAL DEFAULT 0,
        result TEXT DEFAULT '待评定', effective_date TEXT,
        salary_before REAL, salary_after REAL, comments TEXT,
        approved_by TEXT, status TEXT DEFAULT '待审批',
        created_at TEXT DEFAULT (datetime('now')))""",
    # ── Promotion Applications ──
    """CREATE TABLE IF NOT EXISTS promotion_applications (
        id TEXT PRIMARY KEY, employee_id TEXT, employee_name TEXT,
        current_grade TEXT, target_grade TEXT, apply_date TEXT,
        reason TEXT, achievements TEXT, recommender TEXT,
        status TEXT DEFAULT '已提交', reviewer TEXT, review_date TEXT, review_comments TEXT,
        approver TEXT, approve_date TEXT, effective_date TEXT,
        created_at TEXT DEFAULT (datetime('now')))""",
    # ── Bonus Applications ──
    """CREATE TABLE IF NOT EXISTS bonus_applications (
        id TEXT PRIMARY KEY, employee_id TEXT, employee_name TEXT,
        grade TEXT, bonus_type TEXT DEFAULT '贡献奖金',
        amount REAL DEFAULT 0, currency TEXT DEFAULT 'EUR',
        reason TEXT, contribution_desc TEXT, apply_date TEXT, applicant TEXT,
        reviewer TEXT, review_date TEXT, review_status TEXT DEFAULT '待审核',
        approver TEXT, approve_date TEXT, final_status TEXT DEFAULT '待审批',
        paid INTEGER DEFAULT 0, paid_date TEXT,
        created_at TEXT DEFAULT (datetime('now')))""",
    # ── Performance Reviews ──
    """CREATE TABLE IF NOT EXISTS performance_reviews (
        id TEXT PRIMARY KEY, employee_id TEXT, employee_name TEXT,
        grade TEXT, review_period TEXT, review_type TEXT DEFAULT '季度考核',
        dimensions TEXT, scores TEXT, total_score REAL DEFAULT 0,
        rating TEXT, reviewer TEXT, review_date TEXT,
        employee_comments TEXT, reviewer_comments TEXT,
        status TEXT DEFAULT '待评估', created_at TEXT DEFAULT (datetime('now')))""",
    # ── Quotation Templates ──
    """CREATE TABLE IF NOT EXISTS quotation_templates (
        id TEXT PRIMARY KEY, biz_type TEXT, service_type TEXT,
        name TEXT NOT NULL, description TEXT,
        base_price REAL DEFAULT 0, unit TEXT DEFAULT '€/小时',
        volume_tiers TEXT, night_surcharge REAL DEFAULT 0,
        weekend_surcharge REAL DEFAULT 0, holiday_surcharge REAL DEFAULT 0,
        skill_surcharge TEXT, min_hours REAL DEFAULT 0,
        valid_from TEXT, valid_to TEXT, adjust_rules TEXT,
        status TEXT DEFAULT '生效中', created_at TEXT DEFAULT (datetime('now')))""",
    # ── Quotation Records ──
    """CREATE TABLE IF NOT EXISTS quotation_records (
        id TEXT PRIMARY KEY, client_name TEXT, client_contact TEXT,
        template_id TEXT, biz_type TEXT, service_type TEXT,
        warehouse_code TEXT, project_desc TEXT,
        headcount INTEGER DEFAULT 1, estimated_hours REAL DEFAULT 0,
        volume_tier TEXT, base_price REAL DEFAULT 0,
        adjustments TEXT, final_price REAL DEFAULT 0,
        total_amount REAL DEFAULT 0, currency TEXT DEFAULT 'EUR',
        valid_until TEXT, quote_date TEXT,
        quoted_by TEXT, quoted_by_grade TEXT,
        review_status TEXT DEFAULT '待审核', approve_status TEXT DEFAULT '待审批',
        client_response TEXT DEFAULT '待回复', contract_no TEXT, notes TEXT,
        created_at TEXT DEFAULT (datetime('now')))""",
    # ── Employee Files ──
    """CREATE TABLE IF NOT EXISTS employee_files (
        id TEXT PRIMARY KEY, employee_id TEXT NOT NULL,
        category TEXT NOT NULL, file_name TEXT, file_url TEXT,
        file_type TEXT, file_size INTEGER DEFAULT 0,
        description TEXT, upload_date TEXT, uploaded_by TEXT,
        stage TEXT DEFAULT '在职', tags TEXT, confidential INTEGER DEFAULT 0,
        created_at TEXT DEFAULT (datetime('now')))""",
    # ── Leave Types ──
    """CREATE TABLE IF NOT EXISTS leave_types (
        code TEXT PRIMARY KEY, name_zh TEXT, name_en TEXT, name_de TEXT,
        paid INTEGER DEFAULT 1, default_days REAL DEFAULT 0,
        requires_proof INTEGER DEFAULT 0, proof_type TEXT,
        max_consecutive INTEGER DEFAULT 0, min_notice_days INTEGER DEFAULT 0,
        description TEXT)""",
    # ── Leave Balances ──
    """CREATE TABLE IF NOT EXISTS leave_balances (
        id TEXT PRIMARY KEY, employee_id TEXT, year INTEGER,
        leave_type TEXT, total_days REAL DEFAULT 0,
        used_days REAL DEFAULT 0, pending_days REAL DEFAULT 0,
        remaining_days REAL DEFAULT 0,
        UNIQUE(employee_id, year, leave_type))""",
    # ── Leave Requests ──
    """CREATE TABLE IF NOT EXISTS leave_requests (
        id TEXT PRIMARY KEY, employee_id TEXT, employee_name TEXT,
        grade TEXT, warehouse_code TEXT,
        leave_type TEXT, start_date TEXT, end_date TEXT,
        days REAL DEFAULT 0, reason TEXT,
        proof_url TEXT, proof_type TEXT,
        apply_date TEXT, status TEXT DEFAULT '已提交',
        reviewer TEXT, review_date TEXT, review_comments TEXT,
        approver TEXT, approve_date TEXT, cancel_reason TEXT,
        created_at TEXT DEFAULT (datetime('now')))""",
    # ── Expense Claims ──
    """CREATE TABLE IF NOT EXISTS expense_claims (
        id TEXT PRIMARY KEY, employee_id TEXT, employee_name TEXT,
        grade TEXT, department TEXT,
        claim_type TEXT DEFAULT '差旅', amount REAL DEFAULT 0,
        currency TEXT DEFAULT 'EUR', claim_date TEXT,
        description TEXT, items TEXT,
        receipt_urls TEXT, receipt_count INTEGER DEFAULT 0,
        apply_date TEXT, status TEXT DEFAULT '已提交',
        reviewer TEXT, review_date TEXT, review_comments TEXT,
        approver TEXT, approve_date TEXT, approve_comments TEXT,
        paid INTEGER DEFAULT 0, paid_date TEXT, paid_by TEXT, notes TEXT,
        created_at TEXT DEFAULT (datetime('now')))""",
    # ── Employees ──
    """CREATE TABLE IF NOT EXISTS employees (
        id TEXT PRIMARY KEY, name TEXT NOT NULL, phone TEXT, email TEXT,
        nationality TEXT DEFAULT 'CN', gender TEXT DEFAULT '男',
        birth_date TEXT, id_type TEXT DEFAULT '护照', id_number TEXT, address TEXT,
        source TEXT DEFAULT '自有', supplier_id TEXT,
        biz_line TEXT DEFAULT '渊博', department TEXT, primary_wh TEXT, dispatch_whs TEXT,
        position TEXT DEFAULT '库内', grade TEXT DEFAULT 'P1',
        wage_level TEXT DEFAULT 'P1', settle_method TEXT DEFAULT '按小时',
        base_salary REAL DEFAULT 0, hourly_rate REAL DEFAULT 12.0,
        perf_bonus REAL DEFAULT 0, extra_bonus REAL DEFAULT 0,
        tax_mode TEXT DEFAULT '我方报税', tax_no TEXT, tax_id TEXT, tax_class TEXT DEFAULT '1',
        ssn TEXT, iban TEXT, health_insurance TEXT,
        languages TEXT, special_skills TEXT,
        -- 新增字段: 家庭信息和副业
        family_name TEXT,              -- 姓 (Last name)
        given_name TEXT,               -- 名 (First name)
        marital_status TEXT,           -- 婚姻状况
        children_count INTEGER DEFAULT 0, -- 子女数量
        secondary_job INTEGER DEFAULT 0,  -- 是否有副业 (0 无, 1 有)
        annual_leave_days REAL DEFAULT 20, sick_leave_days REAL DEFAULT 30,
        status TEXT DEFAULT '在职', join_date TEXT, leave_date TEXT, pin TEXT,
        file_folder TEXT, has_account INTEGER DEFAULT 0,
        created_at TEXT DEFAULT (datetime('now')), updated_at TEXT DEFAULT (datetime('now')))""",
    # ── Suppliers ──
    """CREATE TABLE IF NOT EXISTS suppliers (
        id TEXT PRIMARY KEY, name TEXT NOT NULL, type TEXT DEFAULT '人力供应商',
        biz_line TEXT DEFAULT '渊博', contract_no TEXT, contract_start TEXT, contract_end TEXT,
        settle_cycle TEXT DEFAULT '月结', currency TEXT DEFAULT 'EUR',
        contact_name TEXT, contact_phone TEXT, contact_email TEXT, address TEXT,
        tax_handle TEXT DEFAULT '供应商自行报税',
        status TEXT DEFAULT '合作中', rating TEXT DEFAULT 'B', notes TEXT,
        created_at TEXT DEFAULT (datetime('now')), updated_at TEXT DEFAULT (datetime('now')))""",
    # ── Warehouses ──
    """CREATE TABLE IF NOT EXISTS warehouses (
        code TEXT PRIMARY KEY, name TEXT NOT NULL, address TEXT,
        manager TEXT, phone TEXT, client_name TEXT, project_no TEXT,
        biz_line TEXT DEFAULT '渊博', client_settle TEXT, note TEXT,
        rate_20gp REAL DEFAULT 150, rate_40gp REAL DEFAULT 280, rate_45hc REAL DEFAULT 330,
        unload_20gp REAL DEFAULT 150, unload_40gp REAL DEFAULT 280, unload_45hc REAL DEFAULT 330,
        emp_cols TEXT, ts_cols TEXT, export_freq TEXT DEFAULT 'Monthly', export_lang TEXT DEFAULT 'zh',
        created_at TEXT DEFAULT (datetime('now')))""",
    # ── NEW: Warehouse Salary Config - 仓库薪资配置表 ──
    """CREATE TABLE IF NOT EXISTS warehouse_salary_config (
        id TEXT PRIMARY KEY,
        warehouse_code TEXT NOT NULL,
        grade TEXT NOT NULL,
        position_type TEXT DEFAULT '库内',
        hourly_rate REAL DEFAULT 0,
        container_rate_20gp REAL DEFAULT 0,
        container_rate_40gp REAL DEFAULT 0,
        container_rate_45hc REAL DEFAULT 0,
        night_bonus_pct REAL DEFAULT 25,
        weekend_bonus_pct REAL DEFAULT 50,
        holiday_bonus_pct REAL DEFAULT 100,
        perf_base REAL DEFAULT 0,
        perf_excellent_bonus REAL DEFAULT 0,
        perf_good_bonus REAL DEFAULT 0,
        special_skill_bonus TEXT,
        settle_method TEXT DEFAULT '按小时',
        effective_from TEXT,
        effective_to TEXT,
        notes TEXT,
        created_at TEXT DEFAULT (datetime('now')),
        updated_at TEXT DEFAULT (datetime('now')),
        UNIQUE(warehouse_code, grade, position_type))""",
    # ── Timesheet ──
    """CREATE TABLE IF NOT EXISTS timesheet (
        id TEXT PRIMARY KEY, employee_id TEXT, employee_name TEXT,
        source TEXT, supplier_id TEXT, biz_line TEXT,
        work_date TEXT, warehouse_code TEXT,
        start_time TEXT, end_time TEXT, hours REAL DEFAULT 0,
        position TEXT, grade TEXT, settle_method TEXT, base_rate REAL DEFAULT 0,
        hourly_pay REAL DEFAULT 0, piece_pay REAL DEFAULT 0,
        perf_bonus REAL DEFAULT 0, other_fee REAL DEFAULT 0,
        ssi_deduct REAL DEFAULT 0, tax_deduct REAL DEFAULT 0, net_pay REAL DEFAULT 0,
        container_no TEXT, container_type TEXT, paper_photo TEXT,
        wh_status TEXT DEFAULT '待仓库审批',
        wh_approver TEXT, wh_approve_time TEXT,
        fin_approver TEXT, fin_approve_time TEXT,
        booked INTEGER DEFAULT 0, notes TEXT,
        created_at TEXT DEFAULT (datetime('now')), updated_at TEXT DEFAULT (datetime('now')))""",
    # ── Container Records ──
    """CREATE TABLE IF NOT EXISTS container_records (
        id TEXT PRIMARY KEY, container_no TEXT, work_date TEXT,
        warehouse_code TEXT, biz_line TEXT,
        container_type TEXT DEFAULT '40GP', load_type TEXT DEFAULT '卸柜',
        team_no TEXT, team_size INTEGER DEFAULT 2, member_ids TEXT,
        start_time TEXT, end_time TEXT, duration_minutes REAL DEFAULT 0,
        client_revenue REAL DEFAULT 0, team_pay REAL DEFAULT 0,
        split_method TEXT DEFAULT '平均',
        photo_door TEXT, photo_seal TEXT,
        photo_open_single TEXT, photo_open_double TEXT,
        photo_empty TEXT, paper_photo TEXT,
        wh_status TEXT DEFAULT '待审核', wh_data_hrs REAL, wh_data_ok INTEGER DEFAULT 0,
        synced_to_timesheet INTEGER DEFAULT 0, notes TEXT,
        created_at TEXT DEFAULT (datetime('now')))""",
    # ── Other tables ──
    """CREATE TABLE IF NOT EXISTS talent_pool (
        id TEXT PRIMARY KEY, name TEXT, phone TEXT,
        source TEXT DEFAULT '自有招聘', supplier_id TEXT, target_biz TEXT,
        nationality TEXT, age INTEGER, position_type TEXT,
        languages TEXT, certificates TEXT,
        pool_status TEXT DEFAULT '储备中', file_folder TEXT,
        notes TEXT, created_at TEXT DEFAULT (datetime('now')))""",
    """CREATE TABLE IF NOT EXISTS schedules (
        id TEXT PRIMARY KEY, employee_id TEXT, employee_name TEXT,
        warehouse_code TEXT, work_date TEXT,
        shift TEXT DEFAULT '白班', start_time TEXT, end_time TEXT,
        position TEXT, biz_line TEXT, status TEXT DEFAULT '已排班',
        actual_in TEXT, actual_out TEXT, notes TEXT,
        created_by TEXT, created_at TEXT DEFAULT (datetime('now')))""",
    """CREATE TABLE IF NOT EXISTS dispatch_needs (
        id TEXT PRIMARY KEY, biz_line TEXT, warehouse_code TEXT,
        position TEXT, headcount INTEGER DEFAULT 1,
        start_date TEXT, end_date TEXT, shift TEXT,
        client_settle TEXT, client_rate REAL, matched_count INTEGER DEFAULT 0,
        status TEXT DEFAULT '待处理', priority TEXT DEFAULT '中',
        requester TEXT, notes TEXT, created_at TEXT DEFAULT (datetime('now')))""",
    """CREATE TABLE IF NOT EXISTS recruit_progress (
        id TEXT PRIMARY KEY, need_id TEXT, candidate_id TEXT,
        source TEXT, supplier_id TEXT, recommend_date TEXT,
        stage TEXT DEFAULT '初筛通过', responsible TEXT,
        status TEXT DEFAULT '进行中', created_at TEXT DEFAULT (datetime('now')))""",
    """CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY, password_hash TEXT NOT NULL,
        display_name TEXT, role TEXT DEFAULT 'worker',
        avatar TEXT, color TEXT DEFAULT '#4f6ef7',
        supplier_id TEXT, warehouse_code TEXT, biz_line TEXT, employee_id TEXT,
        active INTEGER DEFAULT 1, created_at TEXT DEFAULT (datetime('now')))""",
    """CREATE TABLE IF NOT EXISTS permission_overrides (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        role TEXT NOT NULL, module TEXT NOT NULL,
        can_view INTEGER DEFAULT 0, can_create INTEGER DEFAULT 0,
        can_edit INTEGER DEFAULT 0, can_delete INTEGER DEFAULT 0,
        can_export INTEGER DEFAULT 0, can_approve INTEGER DEFAULT 0,
        hidden_fields TEXT DEFAULT '',
        updated_by TEXT, updated_at TEXT DEFAULT (datetime('now')),
        UNIQUE(role, module))""",
    """CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT DEFAULT (datetime('now')),
        username TEXT, user_display TEXT,
        action TEXT, target_table TEXT, target_id TEXT,
        old_value TEXT, new_value TEXT, ip_address TEXT)""",
    """CREATE TABLE IF NOT EXISTS messages (
        id TEXT PRIMARY KEY, channel TEXT DEFAULT 'system',
        from_name TEXT, content TEXT, msg_type TEXT DEFAULT 'info',
        matched INTEGER DEFAULT 0, ref_id TEXT,
        timestamp TEXT DEFAULT (datetime('now')))""",
    """CREATE TABLE IF NOT EXISTS dispatch_transfers (
        id TEXT PRIMARY KEY, employee_id TEXT, dispatch_date TEXT,
        start_date TEXT, end_date TEXT, from_wh TEXT, to_wh TEXT,
        transfer_type TEXT DEFAULT '临时支援', biz_line TEXT,
        approver TEXT, reason TEXT, status TEXT DEFAULT '待审批', notes TEXT,
        created_at TEXT DEFAULT (datetime('now')))""",
    ]
    for sql in tables:
        c.execute(_adapt_sql_for_db(sql))
    
    # Create indexes for better performance and data integrity
    indexes = [
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_timesheet_unique ON timesheet(employee_id, work_date, warehouse_code)",
        "CREATE INDEX IF NOT EXISTS idx_timesheet_date ON timesheet(work_date)",
        "CREATE INDEX IF NOT EXISTS idx_employees_status ON employees(status)",
        "CREATE INDEX IF NOT EXISTS idx_users_employee ON users(employee_id)",
    ]
    for idx_sql in indexes:
        try:
            c.execute(_adapt_sql_for_db(idx_sql))
        except Exception:
            pass  # Index might already exist
    
    conn.commit(); conn.close()

def hash_password(password):
    import hashlib
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(password, hashed):
    return hash_password(password) == hashed

def ensure_demo_users():
    """确保演示账号可用（用于部署后角色测试）"""
    demo_users = [
        ("admin", "admin123", "系统管理员", "admin"),
        ("hr", "hr123", "赵慧(HR)", "hr"),
        ("mgr579", "579pass", "张伟(579)", "mgr"),
        ("fin", "fin123", "孙琳(财务)", "fin"),
        ("wh", "wh123", "王磊(仓库)", "wh"),
        ("worker1", "w123", "张三", "worker"),
    ]
    conn = get_db(); c = conn.cursor()
    for username, password, display_name, role in demo_users:
        c.execute(
            """INSERT INTO users(username,password_hash,display_name,role,active)
               VALUES(?,?,?,?,1)
               ON CONFLICT(username) DO UPDATE SET
                   password_hash=excluded.password_hash,
                   display_name=excluded.display_name,
                   role=excluded.role,
                   active=1""",
            (username, hash_password(password), display_name, role),
        )
    conn.commit(); conn.close()

def seed_data():
    conn = get_db(); c = conn.cursor()
    if c.execute("SELECT COUNT(*) FROM users").fetchone()[0] > 0:
        conn.close(); return

    # ── Grade Levels ──
    grades_data = [
        ("P0","运营",0,"供应商工人","Supplier Worker","Leiharbeiter",11.0,"个人","0",
         '["完成基础任务","遵守安全规定","出勤率≥90%"]',"P1(转正)","[]",0,0),
        ("P1","运营",1,"新人操作员","Junior Operator","Nachwuchsbediener",11.5,"个人","0",
         '["入职安全培训≥80分","2-4周独立完成基础工序,错误率≤5%","扫描/标签正确率≥95%","遵守PPE,无违规","出勤率≥95%","服从管理"]',
         "P2",'[{"dim":"KPI","w":40},{"dim":"质量","w":30},{"dim":"出勤","w":20},{"dim":"态度","w":10}]',0,3),
        ("P2","运营",2,"资深操作员","Senior Operator","Erfahrener Bediener",12.5,"个人","0",
         '["2+工位独立上岗,错误率≤3%","WMS正确率≥98%","产量≥团队90%","5S良好","出勤率≥97%","无重大投诉"]',
         "P3",'[{"dim":"KPI","w":40},{"dim":"质量","w":30},{"dim":"出勤","w":20},{"dim":"态度","w":10}]',3,8),
        ("P3","运营",3,"技能工","Skilled Worker","Facharbeiter",13.5,"带教1-2人","1-2",
         '["持有效叉车/设备证","独立关键工序,失误为0","效率≥100%,质量≥98%","能带教新人","设备点检完整","12月无安全事故"]',
         "P4",'[{"dim":"技能","w":35},{"dim":"效率","w":25},{"dim":"安全","w":20},{"dim":"带教","w":10},{"dim":"出勤","w":10}]',5,10),
        ("P4","运营",4,"组长","Team Leader","Teamleiter",15.0,"3-10人","3-10",
         '["带班3-10人","班组KPI≥仓库平均","按SOP组织班会","新人达标率≥90%","无隐性缺岗","满意度≥75%"]',
         "P5",'[{"dim":"班组KPI","w":35},{"dim":"管理","w":25},{"dim":"安全","w":15},{"dim":"培养","w":15},{"dim":"满意度","w":10}]',5,15),
        ("P5","运营",5,"班组长","Shift Leader","Schichtleiter",17.0,"2-3组","10-30",
         '["独立负责整班次","调配达标率≥95%","异常反馈≥95%","当班无重大事故","季度≥1次面谈","交班完整"]',
         "P6",'[{"dim":"运营","w":35},{"dim":"调配","w":20},{"dim":"安全","w":15},{"dim":"发展","w":15},{"dim":"协调","w":15}]',5,15),
        ("P6","运营",6,"副驻仓经理","Deputy Site Mgr","Stellv. Standortleiter",19.0,"整仓代管","10-50",
         '["独立管理整仓","跟踪SLA/KPI","预警≥2周","年培养≥1名P4","事故数不上升","完成专项任务"]',
         "P7",'[{"dim":"独立管理","w":30},{"dim":"KPI","w":25},{"dim":"培养","w":15},{"dim":"安全","w":15},{"dim":"专项","w":15}]',5,15),
        ("P7","运营",7,"驻仓经理","Site Manager","Standortleiter",22.0,"单仓","10-50",
         '["KPI全年≥目标","安全事故0/轻微+闭环","管理P4-P6+客户沟通","年≥1项改善","流失率≤目标","审计无重大缺陷"]',
         "P8",'[{"dim":"KPI","w":35},{"dim":"客户","w":20},{"dim":"团队","w":20},{"dim":"优化","w":10},{"dim":"安全","w":10},{"dim":"成本","w":5}]',5,20),
        ("P8","运营",8,"区域经理","Regional Manager","Regionalleiter",28.0,"1大区3-6仓","3-6仓",
         '["区域KPI±5%","整改落地≥90%","P7稳定≥95%","客户满意不降","成本受控","年输出≥1接班人"]',
         "P9",'[{"dim":"区域KPI","w":35},{"dim":"客户","w":20},{"dim":"团队","w":20},{"dim":"优化","w":10},{"dim":"财务","w":10},{"dim":"领导力","w":5}]',5,20),
        ("P9","运营",9,"运营总监","Ops Director","Betriebsleiter",35.0,"全公司","全部",
         '["三大区营收≥90%","经营KPI提升","客户续约≥90%","无重大合规","≥1新业务落地","团队稳定≥80%"]',
         "CEO",'[{"dim":"营收","w":30},{"dim":"利润","w":20},{"dim":"客户","w":15},{"dim":"团队","w":15},{"dim":"战略","w":10},{"dim":"合规","w":10}]',0,25),
        ("M1","行政",1,"行政助理","Admin Asst","Verwaltungsasst.",12.0,"个人","0",'["日常行政","文件归档","沟通协调"]',"M2","[]",0,5),
        ("M2","行政",2,"行政专员","Admin Spec","Verwaltungsspezialist",14.0,"个人","0",'["独立行政流程","制度执行","跨部门协调"]',"M3","[]",3,8),
        ("M3","行政",3,"行政主管","Admin Supv","Verwaltungsleiter",17.0,"2-5人","2-5",'["管理团队","制度建设","预算管理"]',"M4","[]",5,12),
        ("M4","行政",4,"行政经理","Admin Mgr","Verwaltungsmanager",22.0,"部门","5-15",'["部门管理","战略支持","流程优化"]',"M5","[]",5,15),
        ("M5","行政",5,"行政总监","Admin Dir","Verwaltungsdirektor",30.0,"全公司","全部",'["体系建设","治理支持","重大项目"]',"",'[]',5,20),
    ]
    for g in grades_data:
        c.execute("""INSERT INTO grade_levels(code,series,level,title_zh,title_en,title_de,
            base_salary,manage_scope,headcount_range,eval_criteria,promotion_path,perf_dimensions,
            adjust_pct_min,adjust_pct_max) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(code) DO NOTHING""", g)

    # ── Leave Types ──
    for lt in [
        ("annual","年假","Annual Leave","Jahresurlaub",1,20,0,"",30,3,"德国法定20天"),
        ("sick","病假","Sick Leave","Krankheit",1,30,1,"AU医生证明",0,0,"第4天起需AU"),
        ("personal","事假","Personal Leave","Sonderurlaub",0,5,0,"",5,1,"无薪事假"),
        ("maternity","产假","Maternity","Mutterschutz",1,98,1,"医院证明",0,0,"产前6周+产后8周"),
        ("marriage","婚假","Marriage","Hochzeitsurlaub",1,3,1,"结婚证明",3,14,""),
        ("bereavement","丧假","Bereavement","Trauerurlaub",1,3,0,"",3,1,"直系亲属"),
    ]:
        c.execute("INSERT INTO leave_types VALUES(?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(code) DO NOTHING", lt)

    # ── Quotation Templates ──
    for q in [
        ("QT-001","人力派遣","普通仓内","仓内操作工派遣","标准拣货/打包/上架",14.50,"€/h",
         '[{"min":1,"max":5,"p":14.50},{"min":6,"max":20,"p":13.80},{"min":21,"max":50,"p":13.20},{"min":51,"max":999,"p":12.80}]',
         2.0,3.0,5.0,'[{"s":"叉车","p":1.5},{"s":"德语B2","p":1.0}]',4,"2026-01-01","2026-12-31",
         '[{"g":"P4","min":-3,"max":3},{"g":"P7","min":-5,"max":5},{"g":"P8","min":-8,"max":8},{"g":"P9","min":-10,"max":10}]'),
        ("QT-002","人力派遣","装卸柜","装卸柜工人派遣","集装箱装卸",16.00,"€/h",
         '[{"min":1,"max":3,"p":16.0},{"min":4,"max":10,"p":15.2},{"min":11,"max":999,"p":14.5}]',
         2.5,4.0,6.0,'[{"s":"叉车","p":1.5},{"s":"重型设备","p":2.0}]',4,"2026-01-01","2026-12-31",
         '[{"g":"P4","min":-3,"max":3},{"g":"P7","min":-5,"max":5},{"g":"P9","min":-10,"max":10}]'),
        ("QT-003","项目承包","整仓承包","整仓运营承包","人力+管理+质控",0,"€/月定制",
         '[]',0,0,0,'[]',0,"2026-01-01","2026-12-31",
         '[{"g":"P8","min":-5,"max":5},{"g":"P9","min":-15,"max":15}]'),
        ("QT-004","人力派遣","管理人员","管理人员派遣","P4-P7级",22.0,"€/h",
         '[{"min":1,"max":2,"p":22.0},{"min":3,"max":5,"p":20.0}]',
         3.0,5.0,8.0,'[]',8,"2026-01-01","2026-12-31",
         '[{"g":"P8","min":-5,"max":5},{"g":"P9","min":-10,"max":10}]'),
        ("QT-005","增值服务","电商包装","Amazon/TEMU电商分拣","电商包装分拣",13.0,"€/h",
         '[{"min":1,"max":10,"p":13.0},{"min":11,"max":30,"p":12.5},{"min":31,"max":999,"p":12.0}]',
         1.5,2.5,4.0,'[]',4,"2026-01-01","2026-12-31",
         '[{"g":"P4","min":-2,"max":2},{"g":"P7","min":-5,"max":5},{"g":"P9","min":-8,"max":8}]'),
    ]:
        c.execute("""INSERT INTO quotation_templates(id,biz_type,service_type,name,description,
            base_price,unit,volume_tiers,night_surcharge,weekend_surcharge,holiday_surcharge,
            skill_surcharge,min_hours,valid_from,valid_to,adjust_rules) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(id) DO NOTHING""", q)

    # ── Users ──
    for u in [
        ("admin","admin123","系统管理员","admin"),("hr","hr123","赵慧(HR)","hr"),
        ("wh_una","una123","王磊(UNA)","wh"),("wh_dhl","dhl123","李娜(DHL)","wh"),
        ("finance","fin123","孙琳(财务)","fin"),("sup001","sup123","陈刚(德信)","sup"),
        ("mgr579","579pass","张伟(579)","mgr"),("worker1","w123","张三","worker"),
    ]:
        c.execute("INSERT INTO users(username,password_hash,display_name,role) VALUES(?,?,?,?)",
                  (u[0],hash_password(u[1]),u[2],u[3]))

    # ── Permissions ──
    ALL_M = ["dashboard","employees","suppliers","talent","dispatch","recruit",
             "timesheet","settlement","warehouse","schedule","templates",
             "clock","container","messages","analytics","admin","logs",
             "grades","quotation","files","leave","expense","performance",
             "mypage","accounts","whsalary"]
    role_perm = {
        "admin": (ALL_M,ALL_M,ALL_M,ALL_M,ALL_M,ALL_M),
        "hr": (["dashboard","employees","suppliers","talent","dispatch","recruit","timesheet","settlement",
                "schedule","templates","messages","analytics","grades","files","leave","expense","performance","accounts","whsalary"],
               ["employees","suppliers","talent","dispatch","recruit","schedule","files","leave","expense","grades","performance","accounts","whsalary"],
               ["employees","suppliers","talent","dispatch","recruit","schedule","timesheet","grades","leave","performance","accounts","whsalary"],
               [],[],["leave","expense"]),
        "wh": (["dashboard","employees","timesheet","warehouse","schedule","clock","container","messages","leave","mypage"],
               ["container","schedule"],["container","schedule"],[],["timesheet","container"],["timesheet","container"]),
        "fin": (["dashboard","employees","timesheet","settlement","suppliers","analytics","expense","quotation"],
               [],[],[],["timesheet","settlement","analytics","expense"],["timesheet","expense"]),
        "sup": (["dashboard","employees","timesheet","settlement"],[],[],[],[],[]),
        "mgr": (["dashboard","employees","suppliers","talent","dispatch","recruit","timesheet","settlement",
                 "warehouse","schedule","templates","clock","container","messages","analytics",
                 "grades","quotation","files","leave","expense","performance","accounts","whsalary"],
                ["employees","talent","dispatch","recruit","container","schedule","quotation","leave","expense","grades","files","performance","accounts","whsalary"],
                ["employees","talent","dispatch","recruit","container","schedule","timesheet","quotation","grades","performance","accounts","whsalary"],
                [],[],["leave","quotation"]),
        "worker": (["clock","container","schedule","leave","expense","mypage"],["container","leave","expense"],[],[],[],[]),
    }
    for role,(v,cr,ed,dl,ex,ap) in role_perm.items():
        for mod in ALL_M:
            c.execute("""INSERT INTO permission_overrides(role,module,can_view,can_create,can_edit,can_delete,can_export,can_approve,hidden_fields)
                VALUES(?,?,?,?,?,?,?,?,?)
                ON CONFLICT(role, module) DO NOTHING""",
                (role,mod,int(mod in v),int(mod in cr),int(mod in ed),int(mod in dl),int(mod in ex),int(mod in ap),""))

    # ── Warehouses ──
    for w in [("UNA","UNA仓库","Köln","王磊","+49-176-1001","UNA Logistics","PRJ-UNA","渊博","按小时","",180,320,380,160,300,350,None,None,"Daily","de"),
              ("DHL","DHL仓库","Düsseldorf","李娜","+49-176-1002","DHL SC","PRJ-DHL","渊博","按小时","",160,300,350,140,280,320,None,None,"Weekly","en"),
              ("W579","579仓库","Duisburg","张伟","+49-176-1003","579 Express","PRJ-579","579","按小时","",150,280,330,130,260,300,None,None,"Monthly","zh"),
              ("CMA","CMA仓库","Essen","赵六","+49-176-1004","CMA CGM","PRJ-CMA","渊博","按柜","",170,310,360,150,290,340,None,None,"Monthly","en"),
              ("EMR","Emmerich仓库","Emmerich","周七","+49-176-1005","Emmerich Log","PRJ-EMR","渊博","按件","",160,290,340,140,270,310,None,None,"Monthly","de")]:
        c.execute("INSERT INTO warehouses VALUES("+",".join(["?"]*21)+")", w+("",))

    # ── NEW: Warehouse Salary Config ──
    wh_salary_configs = [
        # UNA仓库薪资配置
        ("WSC-UNA-P0-库内","UNA","P0","库内",11.5,0,0,0,25,50,100,0,50,30,'[]',"按小时","2026-01-01","2026-12-31",""),
        ("WSC-UNA-P1-库内","UNA","P1","库内",12.0,0,0,0,25,50,100,50,80,50,'[{"skill":"叉车","bonus":1.5}]',"按小时","2026-01-01","2026-12-31",""),
        ("WSC-UNA-P2-库内","UNA","P2","库内",13.0,0,0,0,25,50,100,80,100,60,'[{"skill":"叉车","bonus":1.5}]',"按小时","2026-01-01","2026-12-31",""),
        ("WSC-UNA-P2-装卸","UNA","P2","装卸",14.0,180,320,380,25,50,100,100,120,80,'[{"skill":"叉车","bonus":2.0}]',"按柜","2026-01-01","2026-12-31",""),
        ("WSC-UNA-P3-装卸","UNA","P3","装卸",15.0,200,360,420,25,50,100,120,150,100,'[{"skill":"叉车","bonus":2.0}]',"按柜","2026-01-01","2026-12-31",""),
        ("WSC-UNA-P4-管理","UNA","P4","管理",16.0,0,0,0,25,50,100,150,200,120,'[]',"按小时","2026-01-01","2026-12-31",""),
        # DHL仓库薪资配置
        ("WSC-DHL-P0-库内","DHL","P0","库内",11.0,0,0,0,20,40,80,0,40,25,'[]',"按小时","2026-01-01","2026-12-31",""),
        ("WSC-DHL-P1-库内","DHL","P1","库内",11.5,0,0,0,20,40,80,40,60,40,'[]',"按小时","2026-01-01","2026-12-31",""),
        ("WSC-DHL-P2-库内","DHL","P2","库内",12.5,0,0,0,20,40,80,60,80,50,'[{"skill":"德语B2","bonus":1.0}]',"按小时","2026-01-01","2026-12-31",""),
        ("WSC-DHL-P2-装卸","DHL","P2","装卸",13.5,160,300,350,20,40,80,80,100,60,'[{"skill":"叉车","bonus":1.5}]',"按柜","2026-01-01","2026-12-31",""),
        ("WSC-DHL-P3-装卸","DHL","P3","装卸",14.5,180,340,400,20,40,80,100,130,80,'[{"skill":"叉车","bonus":1.5}]',"按柜","2026-01-01","2026-12-31",""),
        # W579仓库薪资配置
        ("WSC-579-P0-库内","W579","P0","库内",10.5,0,0,0,30,60,120,0,30,20,'[]',"按小时","2026-01-01","2026-12-31",""),
        ("WSC-579-P1-库内","W579","P1","库内",11.0,0,0,0,30,60,120,30,50,35,'[]',"按小时","2026-01-01","2026-12-31",""),
        ("WSC-579-P2-库内","W579","P2","库内",12.0,0,0,0,30,60,120,50,70,45,'[]',"按小时","2026-01-01","2026-12-31",""),
        ("WSC-579-P2-装卸","W579","P2","装卸",13.0,150,280,330,30,60,120,70,90,55,'[{"skill":"叉车","bonus":1.5}]',"按柜","2026-01-01","2026-12-31",""),
        # CMA仓库薪资配置
        ("WSC-CMA-P0-库内","CMA","P0","库内",11.0,0,0,0,25,50,100,0,35,25,'[]',"按小时","2026-01-01","2026-12-31",""),
        ("WSC-CMA-P2-装卸","CMA","P2","装卸",13.5,170,310,360,25,50,100,80,100,65,'[{"skill":"叉车","bonus":1.8}]',"按柜","2026-01-01","2026-12-31",""),
        # EMR仓库薪资配置
        ("WSC-EMR-P0-库内","EMR","P0","库内",10.8,0,0,0,25,50,100,0,30,20,'[]',"按小时","2026-01-01","2026-12-31",""),
        ("WSC-EMR-P2-装卸","EMR","P2","装卸",13.0,160,290,340,25,50,100,70,90,55,'[{"skill":"叉车","bonus":1.5}]',"按柜","2026-01-01","2026-12-31",""),
        ("WSC-EMR-P3-装卸","EMR","P3","装卸",14.0,180,320,380,25,50,100,90,120,75,'[{"skill":"叉车","bonus":1.5}]',"按柜","2026-01-01","2026-12-31",""),
        ("WSC-EMR-P4-管理","EMR","P4","管理",15.5,0,0,0,25,50,100,130,180,110,'[]',"按小时","2026-01-01","2026-12-31",""),
    ]
    for wsc in wh_salary_configs:
        c.execute("""INSERT INTO warehouse_salary_config(id,warehouse_code,grade,position_type,
            hourly_rate,container_rate_20gp,container_rate_40gp,container_rate_45hc,
            night_bonus_pct,weekend_bonus_pct,holiday_bonus_pct,perf_base,perf_excellent_bonus,perf_good_bonus,
            special_skill_bonus,settle_method,effective_from,effective_to,notes) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(id) DO NOTHING""", wsc)

    # ── Suppliers ──
    for s in [("SUP-001","德信人力","人力供应商","渊博","CT-2025-001","2025-01-01","2026-12-31","月结","EUR","陈刚","+49-176-2001","chen@dexin.de","Köln","供应商自行报税","合作中","A",""),
              ("SUP-002","欧华劳务","人力供应商","渊博","CT-2025-002","2025-03-01","2026-06-30","半月结","EUR","赵丽","+49-176-2002","zhao@ouhua.de","Düsseldorf","我方代报税","合作中","B",""),
              ("SUP-003","环球人才","人力供应商","579","CT-2025-003","2025-06-01","2026-12-31","月结","EUR","孙明","+49-176-2003","sun@global.de","Duisburg","供应商自行报税","合作中","A","")]:
        c.execute("INSERT INTO suppliers VALUES("+",".join(["?"]*19)+")", s+("",""))

    # ── Employees ──
    emps = [
        ("YB-001","张三","+49-176-0001","zh.san@mail.de","CN","男","1990-05-15","护照","E12345001","Hamburg 45","自有",None,"渊博","运营部","UNA","UNA,DHL","装卸","P2","P2","按小时",12.5,13.0,0,0,"我方报税","T001","12345678901","1","SS-001","DE89370400440532013000","AOK","中,德","叉车证",20,30,"在职","2025-03-15",None,"1001","YB-001",0),
        ("YB-002","李四","+49-176-0002","li.si@mail.de","CN","男","1988-11-20","护照","E12345002","Berlin 12","自有",None,"渊博","运营部","DHL","DHL,UNA","库内","P2","P2","按小时",12.5,12.0,0,0,"我方报税","T002","23456789012","1","SS-002","DE89370400440532013001","TK","中,英",None,20,30,"在职","2025-06-01",None,"1002","YB-002",0),
        ("YB-003","王五","+49-176-0003",None,"VN","男","1992-03-10","签证","E12345003","Hamburg 78","供应商","SUP-001","渊博","运营部","UNA","UNA","装卸","P0","P0","按小时",11.0,11.0,0,0,"供应商报税","","","","","","","越,德",None,20,30,"在职","2025-09-01",None,"1003","YB-003",0),
        ("YB-004","阮氏花","+49-176-0004",None,"VN","女","1995-07-22","签证","E12345004","Hamburg 90","供应商","SUP-001","渊博","运营部","UNA","UNA","库内","P0","P0","按件",11.0,11.0,0,0,"供应商报税","","","","","","","越",None,20,30,"在职","2025-10-15",None,"1004","YB-004",0),
        ("YB-005","陈大明","+49-176-0005",None,"CN","男","1985-01-30","护照","E12345005","Berlin 56","供应商","SUP-002","渊博","运营部","DHL","DHL,CMA","装卸","P3","P3","按柜",13.5,13.5,0,0,"我方报税","T005","34567890123","3","SS-005","DE55556666777788889999","AOK","中,德,英","叉车证",20,30,"在职","2024-06-01",None,"1005","YB-005",0),
        ("YB-006","刘芳","+49-176-0006",None,"CN","女","1993-09-08","护照","E12345006","Frankfurt 34","自有",None,"579","运营部","W579","W579","库内","P2","P2","按小时",12.5,12.0,0,0,"我方报税","T006","45678901234","1","SS-006","DE66667777888899990000","AOK","中","健康证",20,30,"在职","2025-08-01",None,"1006","YB-006",0),
        ("YB-007","黄强","+49-176-0007",None,"CN","男","1991-12-05","护照","E12345007","Frankfurt 67","供应商","SUP-003","579","运营部","W579","W579","装卸","P0","P0","按小时",11.0,12.0,0,0,"供应商报税","","","","","","","中",None,20,30,"在职","2026-01-10",None,"1007","YB-007",0),
        ("YB-008","Maria K.","+49-176-0008",None,"DE","女","1994-04-18","身份证","DE-ID-008","Düsseldorf 22","自有",None,"渊博","运营部","DHL","DHL","库内","P2","P2","按小时",12.5,14.0,0,0,"我方报税","T008","56789012345","1","SS-008","DE89370400440532013007","TK","德,英",None,20,30,"在职","2025-04-01",None,"1008","YB-008",0),
        ("YB-009","赵六","+49-176-0009",None,"CN","男","1987-08-25","护照","E12345009","Essen 15","供应商","SUP-001","渊博","运营部","CMA","CMA,EMR","装卸","P0","P0","按小时",11.0,12.5,0,0,"供应商报税","","","","","","","中,德","叉车证",20,30,"在职","2025-11-01",None,"1009","YB-009",0),
        ("YB-010","武志强","+49-176-0010",None,"CN","男","1990-02-14","护照","E12345010","Emmerich 8","自有",None,"渊博","运营部","EMR","EMR,CMA","装卸","P4","P4","按小时",15.0,15.0,0,0,"我方报税","T010","67890123456","1","SS-010","DE89370400440532013009","AOK","中,德,英","叉车证",20,30,"在职","2024-01-15",None,"1010","YB-010",0),
        ("YB-011","赵慧","+49-176-0020",None,"CN","女","1990-06-15","护照","E12345020","Köln 88","自有",None,"渊博","人事部","UNA","","HR专员","M2","M2","月薪",14.0,0,0,0,"我方报税","T020","88901234567","1","SS-020","DE11112222333344445555","AOK","中,德,英","",20,30,"在职","2024-03-01",None,"2001","YB-011",0),
        ("YB-012","孙琳","+49-176-0021",None,"CN","女","1988-03-20","护照","E12345021","Köln 99","自有",None,"渊博","财务部","UNA","","财务专员","M2","M2","月薪",14.0,0,0,0,"我方报税","T021","99012345678","1","SS-021","DE22223333444455556666","TK","中,德","",20,30,"在职","2024-05-01",None,"2002","YB-012",0),
    ]
    for e in emps:
        c.execute("INSERT INTO employees(id,name,phone,email,nationality,gender,birth_date,id_type,id_number,address,source,supplier_id,biz_line,department,primary_wh,dispatch_whs,position,grade,wage_level,settle_method,base_salary,hourly_rate,perf_bonus,extra_bonus,tax_mode,tax_no,tax_id,tax_class,ssn,iban,health_insurance,languages,special_skills,annual_leave_days,sick_leave_days,status,join_date,leave_date,pin,file_folder,has_account) VALUES("+",".join(["?"]*41)+")", e)

    # ── Leave Balances ──
    for e in emps:
        for lt,total in [("annual",20),("sick",30),("personal",5)]:
            used = random.randint(0,3) if lt!="sick" else random.randint(0,2)
            c.execute("INSERT INTO leave_balances VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(id) DO NOTHING",
                (f"LB-{e[0]}-2026-{lt}",e[0],2026,lt,total,used,0,total-used))

    # ── Sample data ──
    for lr in [
        ("LR-001","YB-001","张三","P2","UNA","annual","2026-02-20","2026-02-21",2,"家庭事务",None,None,"2026-02-10","已批准","王磊","2026-02-11","同意",None,None,None),
        ("LR-002","YB-006","刘芳","P2","W579","sick","2026-02-05","2026-02-07",3,"感冒",None,"AU","2026-02-05","已批准","张伟","2026-02-05","AU已提供",None,None,None),
        ("LR-003","YB-008","Maria K.","P2","DHL","personal","2026-02-18","2026-02-18",1,"私事",None,None,"2026-02-15","待审批",None,None,None,None,None,None),
    ]:
        c.execute("INSERT INTO leave_requests(id,employee_id,employee_name,grade,warehouse_code,leave_type,start_date,end_date,days,reason,proof_url,proof_type,apply_date,status,reviewer,review_date,review_comments,approver,approve_date,cancel_reason) VALUES("+",".join(["?"]*20)+")", lr)

    for ec in [
        ("EC-001","YB-010","武志强","P4","运营部","差旅",85.50,"EUR","2026-02-01","CMA出差交通费",'[{"item":"火车票","amount":42.5},{"item":"午餐","amount":15},{"item":"出租车","amount":28}]',None,3,"2026-02-03","已批准","王磊","2026-02-04","票据齐全","孙琳","2026-02-05","",1,"2026-02-10","孙琳",""),
        ("EC-002","YB-001","张三","P2","运营部","工具",23.00,"EUR","2026-02-08","安全手套",'[{"item":"安全手套2双","amount":23}]',None,1,"2026-02-08","待审批",None,None,None,None,None,None,0,None,None,""),
    ]:
        c.execute("INSERT INTO expense_claims(id,employee_id,employee_name,grade,department,claim_type,amount,currency,claim_date,description,items,receipt_urls,receipt_count,apply_date,status,reviewer,review_date,review_comments,approver,approve_date,approve_comments,paid,paid_date,paid_by,notes) VALUES("+",".join(["?"]*25)+")", ec)

    for ef in [
        ("EF-001","YB-001","入职文件","劳动合同_张三.pdf",None,"pdf",0,"劳动合同","2025-03-15","hr","入职","合同",1),
        ("EF-002","YB-001","证件","护照_张三.pdf",None,"pdf",0,"护照扫描件","2025-03-15","hr","入职","证件",1),
        ("EF-003","YB-005","证件","叉车证_陈大明.pdf",None,"pdf",0,"叉车操作证","2024-06-01","hr","入职","资格证",1),
        ("EF-004","YB-010","晋升","P4晋升评定表.pdf",None,"pdf",0,"P3→P4晋升","2025-06-01","hr","在职","晋升",0),
    ]:
        c.execute("INSERT INTO employee_files(id,employee_id,category,file_name,file_url,file_type,file_size,description,upload_date,uploaded_by,stage,tags,confidential) VALUES("+",".join(["?"]*13)+")", ef)

    for pr in [
        ("PR-001","YB-001","张三","P2","2026-Q1","季度考核",'[{"dim":"KPI","w":40},{"dim":"质量","w":30},{"dim":"出勤","w":20},{"dim":"态度","w":10}]','[{"dim":"KPI","s":85},{"dim":"质量","s":90},{"dim":"出勤","s":95},{"dim":"态度","s":88}]',88.5,"良好(B)","王磊","2026-01-31","","表现稳定","已完成"),
        ("PR-002","YB-010","武志强","P4","2026-Q1","季度考核",'[{"dim":"班组KPI","w":35},{"dim":"管理","w":25},{"dim":"安全","w":15},{"dim":"培养","w":15},{"dim":"满意度","w":10}]','[{"dim":"班组KPI","s":92},{"dim":"管理","s":88},{"dim":"安全","s":100},{"dim":"培养","s":85},{"dim":"满意度","s":90}]',91.1,"优秀(A)","admin","2026-01-31","","建议P5晋升","已完成"),
    ]:
        c.execute("INSERT INTO performance_reviews(id,employee_id,employee_name,grade,review_period,review_type,dimensions,scores,total_score,rating,reviewer,review_date,employee_comments,reviewer_comments,status) VALUES("+",".join(["?"]*15)+")", pr)

    for qr in [
        ("QR-001","UNA Logistics","Hr. Schmidt","QT-001","人力派遣","普通仓内","UNA","UNA拣货派遣",8,160,"6-20人",13.80,None,13.80,2208.0,"EUR","2026-03-31","2026-02-01","admin","P9","已通过","已通过","已接受","PRJ-UNA",""),
        ("QR-002","579 Express","张经理","QT-002","人力派遣","装卸柜","W579","579装卸派遣",4,80,"4-10人",15.20,None,15.20,1216.0,"EUR","2026-04-30","2026-02-05","mgr579","P7","待审核","待审批","待回复",None,""),
    ]:
        c.execute("INSERT INTO quotation_records(id,client_name,client_contact,template_id,biz_type,service_type,warehouse_code,project_desc,headcount,estimated_hours,volume_tier,base_price,adjustments,final_price,total_amount,currency,valid_until,quote_date,quoted_by,quoted_by_grade,review_status,approve_status,client_response,contract_no,notes) VALUES("+",".join(["?"]*25)+")", qr)

    # ── Timesheet ──
    random.seed(42)
    emp_ts = [("YB-001","张三","自有",None,"渊博","UNA","装卸","P2","按小时",14),
              ("YB-002","李四","自有",None,"渊博","DHL","库内","P2","按小时",12.5),
              ("YB-005","陈大明","供应商","SUP-002","渊博","DHL","装卸","P3","按柜",14.5),
              ("YB-006","刘芳","自有",None,"579","W579","库内","P2","按小时",12),
              ("YB-010","武志强","自有",None,"渊博","EMR","装卸","P4","按小时",15.5)]
    ts_id = 1
    for d in range(3,13):
        dt = f"2026-02-{d:02d}"
        for eid,enm,src,supid,biz,wh,pos,grd,settle,rate in emp_ts:
            sH=7+random.randint(0,2); eH=sH+4+random.randint(0,5); hrs=eH-sH
            hP=round(rate*hrs,2); si=round(hP*.12,2) if src=="自有" else 0; tx=round(hP*.08,2) if src=="自有" else 0
            net=round(hP-si-tx,2)
            c.execute("""INSERT INTO timesheet(id,employee_id,employee_name,source,supplier_id,biz_line,
                work_date,warehouse_code,start_time,end_time,hours,position,grade,settle_method,base_rate,
                hourly_pay,ssi_deduct,tax_deduct,net_pay,wh_status) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (f"WT-{ts_id:04d}",eid,enm,src,supid,biz,dt,wh,f"{sH:02d}:00",f"{eH:02d}:00",hrs,pos,grd,settle,rate,hP,si,tx,net,
                 random.choice(["已入账","已入账","待财务确认","待仓库审批"])))
            ts_id += 1

    conn.commit(); conn.close()
    print("✅ DB seeded with all modules")

if __name__ == "__main__":
    import sys
    if os.path.exists(DB_PATH): os.remove(DB_PATH)
    init_db(); seed_data()
