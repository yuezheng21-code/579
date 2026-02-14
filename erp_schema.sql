-- ERP Database Schema (SQLite/Postgres compatible)

-- Employees table: stores basic employee information and HR data
CREATE TABLE IF NOT EXISTS employees (
    id             TEXT PRIMARY KEY,
    name           TEXT NOT NULL,
    family_name    TEXT,
    given_name     TEXT,
    gender         TEXT,
    birth_date     DATE,
    birth_place    TEXT,
    address        TEXT,
    social_number  TEXT,   -- Sozialversicherungsnummer (养老保险号)
    tax_id         TEXT,   -- Steueridentifikationgsnummer (个人税号)
    tax_class      TEXT,   -- Steuerklasse (税卡级别)
    marital_status TEXT,   -- 婚姻状况
    children_count INTEGER,
    nationality    TEXT,
    health_insurance TEXT,
    secondary_job  BOOLEAN DEFAULT 0, -- 是否有副业
    grade          TEXT,   -- 职级 (P1-P9)
    position       TEXT,   -- 岗位名称
    primary_wh     TEXT,   -- 主仓库编码
    dispatch_whs   TEXT,   -- 可派遣仓库编码，逗号分隔
    hourly_rate    REAL,   -- 默认小时工资
    has_account    INTEGER DEFAULT 0,
    status         TEXT DEFAULT '在职', -- 在职/离职/休假等
    entry_date     DATE,
    created_at     TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at     TEXT
);

-- Users table: application login accounts associated with employees
CREATE TABLE IF NOT EXISTS users (
    username       TEXT PRIMARY KEY,
    password_hash  TEXT NOT NULL,
    display_name   TEXT,
    role           TEXT NOT NULL, -- admin, manager, worker
    employee_id    TEXT,
    warehouse_code TEXT,          -- 账号所属仓库
    biz_line       TEXT,          -- 业务线
    active         INTEGER DEFAULT 1,
    created_at     TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at     TEXT,
    FOREIGN KEY(employee_id) REFERENCES employees(id)
);

-- Grade levels table: defines base salary and description for each grade (P1–P9)
CREATE TABLE IF NOT EXISTS grade_levels (
    code        TEXT PRIMARY KEY, -- e.g. P1, P2, ..., P9
    name        TEXT,
    base_salary REAL,   -- default hourly base
    description TEXT
);

-- Suppliers table: lists workforce suppliers and related info
CREATE TABLE IF NOT EXISTS suppliers (
    id               TEXT PRIMARY KEY,
    name             TEXT NOT NULL,
    supplier_type    TEXT,        -- 类型，如劳务派遣公司
    business_line    TEXT,        -- 业务线
    contract_start   DATE,
    contract_end     DATE,
    contact_name     TEXT,
    contact_phone    TEXT,
    email            TEXT,
    address          TEXT,
    status           TEXT DEFAULT 'active',
    remark           TEXT,
    created_at       TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at       TEXT
);

-- Warehouses table: list of warehouses where employees can work
CREATE TABLE IF NOT EXISTS warehouses (
    code        TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    location    TEXT,
    type        TEXT,   -- 客户仓/自有仓等
    remark      TEXT,
    created_at  TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at  TEXT
);

-- Warehouse salary config: overrides hourly rates per warehouse/grade/position
CREATE TABLE IF NOT EXISTS warehouse_salary_config (
    id            TEXT PRIMARY KEY,
    warehouse_code TEXT NOT NULL,
    grade         TEXT NOT NULL,
    position_type TEXT DEFAULT '库内',
    hourly_rate   REAL NOT NULL,
    base_salary   REAL,
    overtime_rate REAL,
    remark        TEXT,
    created_at    TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at    TEXT,
    FOREIGN KEY(warehouse_code) REFERENCES warehouses(code)
);

-- Timesheet table: records employees' work hours, pay and net pay
CREATE TABLE IF NOT EXISTS timesheet (
    id            TEXT PRIMARY KEY,
    employee_id   TEXT NOT NULL,
    grade         TEXT,
    position      TEXT,
    warehouse_code TEXT NOT NULL,
    work_date     DATE NOT NULL,
    start_time    TEXT,
    end_time      TEXT,
    hours         REAL NOT NULL,
    hourly_pay    REAL,   -- gross pay per hour
    net_pay       REAL,   -- net pay after deductions
    wh_status     TEXT,   -- 工作仓库状态，正常/异常等
    remarks       TEXT,
    created_at    TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at    TEXT,
    FOREIGN KEY(employee_id) REFERENCES employees(id),
    FOREIGN KEY(warehouse_code) REFERENCES warehouses(code)
);

-- Leave balances table: tracks annual leave and other types of leave per employee
CREATE TABLE IF NOT EXISTS leave_balances (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    employee_id    TEXT NOT NULL,
    year           INTEGER NOT NULL,
    leave_type     TEXT NOT NULL, -- e.g. annual, sick, maternity
    total_days     REAL NOT NULL,
    used_days      REAL DEFAULT 0,
    remaining_days REAL NOT NULL,
    created_at     TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at     TEXT,
    FOREIGN KEY(employee_id) REFERENCES employees(id)
);

-- Payroll summary table: aggregates monthly pay for each employee
CREATE TABLE IF NOT EXISTS payroll_summary (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    employee_id   TEXT NOT NULL,
    month         TEXT NOT NULL, -- YYYY-MM
    total_hours   REAL,
    gross_pay     REAL,
    deductions    REAL,
    net_pay       REAL,
    generated_at  TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(employee_id) REFERENCES employees(id)
);

-- Roles and permissions can be extended as needed, e.g., to define who can approve timesheets or payroll.
