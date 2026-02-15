-- ============================================================================
-- 渊博+579 HR V6 数据库架构参考文件 (Schema Reference File)
-- ============================================================================
-- 此文件仅供参考。运行时的权威架构定义在 database.py 的 init_db() 函数中。
-- This file is for reference only. The authoritative schema at runtime is 
-- defined in the init_db() function of database.py.
-- ============================================================================

-- ── Grade Levels P0-P9/M1-M5 ──
CREATE TABLE IF NOT EXISTS grade_levels (
    code TEXT PRIMARY KEY, series TEXT NOT NULL, level INTEGER,
    title_zh TEXT, title_en TEXT, title_de TEXT,
    base_salary REAL DEFAULT 0, salary_currency TEXT DEFAULT 'EUR',
    manage_scope TEXT, headcount_range TEXT,
    eval_criteria TEXT, promotion_path TEXT, promotion_conditions TEXT,
    perf_dimensions TEXT, bonus_eligible INTEGER DEFAULT 1,
    adjust_pct_min REAL DEFAULT 0, adjust_pct_max REAL DEFAULT 0,
    description TEXT, created_at TEXT DEFAULT (datetime('now')));

-- ── Grade Evaluations ──
CREATE TABLE IF NOT EXISTS grade_evaluations (
    id TEXT PRIMARY KEY, employee_id TEXT, current_grade TEXT, target_grade TEXT,
    eval_type TEXT DEFAULT '晋升评定', eval_date TEXT, evaluator TEXT,
    criteria_results TEXT, total_score REAL DEFAULT 0,
    result TEXT DEFAULT '待评定', effective_date TEXT,
    salary_before REAL, salary_after REAL, comments TEXT,
    approved_by TEXT, status TEXT DEFAULT '待审批',
    created_at TEXT DEFAULT (datetime('now')));

-- ── Promotion Applications ──
CREATE TABLE IF NOT EXISTS promotion_applications (
    id TEXT PRIMARY KEY, employee_id TEXT, employee_name TEXT,
    current_grade TEXT, target_grade TEXT, apply_date TEXT,
    reason TEXT, achievements TEXT, recommender TEXT,
    status TEXT DEFAULT '已提交', reviewer TEXT, review_date TEXT, review_comments TEXT,
    approver TEXT, approve_date TEXT, effective_date TEXT,
    created_at TEXT DEFAULT (datetime('now')));

-- ── Bonus Applications ──
CREATE TABLE IF NOT EXISTS bonus_applications (
    id TEXT PRIMARY KEY, employee_id TEXT, employee_name TEXT,
    grade TEXT, bonus_type TEXT DEFAULT '贡献奖金',
    amount REAL DEFAULT 0, currency TEXT DEFAULT 'EUR',
    reason TEXT, contribution_desc TEXT, apply_date TEXT, applicant TEXT,
    reviewer TEXT, review_date TEXT, review_status TEXT DEFAULT '待审核',
    approver TEXT, approve_date TEXT, final_status TEXT DEFAULT '待审批',
    paid INTEGER DEFAULT 0, paid_date TEXT,
    created_at TEXT DEFAULT (datetime('now')));

-- ── Performance Reviews ──
CREATE TABLE IF NOT EXISTS performance_reviews (
    id TEXT PRIMARY KEY, employee_id TEXT, employee_name TEXT,
    grade TEXT, review_period TEXT, review_type TEXT DEFAULT '季度考核',
    dimensions TEXT, scores TEXT, total_score REAL DEFAULT 0,
    rating TEXT, reviewer TEXT, review_date TEXT,
    employee_comments TEXT, reviewer_comments TEXT,
    status TEXT DEFAULT '待评估', created_at TEXT DEFAULT (datetime('now')));

-- ── Quotation Templates ──
CREATE TABLE IF NOT EXISTS quotation_templates (
    id TEXT PRIMARY KEY, biz_type TEXT, service_type TEXT,
    name TEXT NOT NULL, description TEXT,
    base_price REAL DEFAULT 0, unit TEXT DEFAULT '€/小时',
    volume_tiers TEXT, night_surcharge REAL DEFAULT 0,
    weekend_surcharge REAL DEFAULT 0, holiday_surcharge REAL DEFAULT 0,
    skill_surcharge TEXT, min_hours REAL DEFAULT 0,
    valid_from TEXT, valid_to TEXT, adjust_rules TEXT,
    status TEXT DEFAULT '生效中', created_at TEXT DEFAULT (datetime('now')));

-- ── Quotation Records ──
CREATE TABLE IF NOT EXISTS quotation_records (
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
    created_at TEXT DEFAULT (datetime('now')));

-- ── Employee Files ──
CREATE TABLE IF NOT EXISTS employee_files (
    id TEXT PRIMARY KEY, employee_id TEXT NOT NULL,
    category TEXT NOT NULL, file_name TEXT, file_url TEXT,
    file_type TEXT, file_size INTEGER DEFAULT 0,
    description TEXT, upload_date TEXT, uploaded_by TEXT,
    stage TEXT DEFAULT '在职', tags TEXT, confidential INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now')));

-- ── Leave Types ──
CREATE TABLE IF NOT EXISTS leave_types (
    code TEXT PRIMARY KEY, name_zh TEXT, name_en TEXT, name_de TEXT,
    paid INTEGER DEFAULT 1, default_days REAL DEFAULT 0,
    requires_proof INTEGER DEFAULT 0, proof_type TEXT,
    max_consecutive INTEGER DEFAULT 0, min_notice_days INTEGER DEFAULT 0,
    description TEXT);

-- ── Leave Balances ──
CREATE TABLE IF NOT EXISTS leave_balances (
    id TEXT PRIMARY KEY, employee_id TEXT, year INTEGER,
    leave_type TEXT, total_days REAL DEFAULT 0,
    used_days REAL DEFAULT 0, pending_days REAL DEFAULT 0,
    remaining_days REAL DEFAULT 0,
    UNIQUE(employee_id, year, leave_type));

-- ── Leave Requests ──
CREATE TABLE IF NOT EXISTS leave_requests (
    id TEXT PRIMARY KEY, employee_id TEXT, employee_name TEXT,
    grade TEXT, warehouse_code TEXT,
    leave_type TEXT, start_date TEXT, end_date TEXT,
    days REAL DEFAULT 0, reason TEXT,
    proof_url TEXT, proof_type TEXT,
    apply_date TEXT, status TEXT DEFAULT '已提交',
    reviewer TEXT, review_date TEXT, review_comments TEXT,
    approver TEXT, approve_date TEXT, cancel_reason TEXT,
    created_at TEXT DEFAULT (datetime('now')));

-- ── Expense Claims ──
CREATE TABLE IF NOT EXISTS expense_claims (
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
    created_at TEXT DEFAULT (datetime('now')));

-- ── Employees ──
CREATE TABLE IF NOT EXISTS employees (
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
    -- 花名册增强: 合同与派遣信息
    contract_type TEXT DEFAULT '劳动合同',  -- 合同类型 (劳动合同/劳务合同/兼职合同)
    dispatch_type TEXT,                      -- 派遣类型 (纯派遣/流程承包/区块承包/整仓承包)
    contract_start TEXT,                     -- 合同开始日期
    contract_end TEXT,                       -- 合同结束日期
    emergency_contact TEXT,                  -- 紧急联系人
    emergency_phone TEXT,                    -- 紧急联系人电话
    work_permit_no TEXT,                     -- 工作许可证号
    work_permit_expiry TEXT,                 -- 工作许可证到期日
    work_hours_per_week REAL DEFAULT 40,     -- 每周工作小时数
    annual_leave_days REAL DEFAULT 20, sick_leave_days REAL DEFAULT 30,
    status TEXT DEFAULT '在职', join_date TEXT, leave_date TEXT, pin TEXT,
    file_folder TEXT, has_account INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now')), updated_at TEXT DEFAULT (datetime('now')));

-- ── Suppliers ──
CREATE TABLE IF NOT EXISTS suppliers (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, type TEXT DEFAULT '人力供应商',
    biz_line TEXT DEFAULT '渊博', contract_no TEXT, contract_start TEXT, contract_end TEXT,
    settle_cycle TEXT DEFAULT '月结', currency TEXT DEFAULT 'EUR',
    contact_name TEXT, contact_phone TEXT, contact_email TEXT, address TEXT,
    tax_handle TEXT DEFAULT '供应商自行报税',
    -- 供应商模块增强
    service_scope TEXT,                      -- 服务范围
    dispatch_types TEXT,                     -- 可提供派遣类型 (JSON: ["纯派遣","流程承包"...])
    bank_name TEXT,                          -- 开户银行
    bank_account TEXT,                       -- 银行账号
    max_headcount INTEGER DEFAULT 0,         -- 最大供应人数
    current_headcount INTEGER DEFAULT 0,     -- 当前在岗人数
    status TEXT DEFAULT '合作中', rating TEXT DEFAULT 'B', notes TEXT,
    created_at TEXT DEFAULT (datetime('now')), updated_at TEXT DEFAULT (datetime('now')));

-- ── Warehouses (客户仓库 - 第三方劳务派遣) ──
CREATE TABLE IF NOT EXISTS warehouses (
    code TEXT PRIMARY KEY, name TEXT NOT NULL, address TEXT,
    manager TEXT, phone TEXT, client_name TEXT, project_no TEXT,
    biz_line TEXT DEFAULT '渊博', client_settle TEXT, note TEXT,
    rate_20gp REAL DEFAULT 150, rate_40gp REAL DEFAULT 280, rate_45hc REAL DEFAULT 330,
    unload_20gp REAL DEFAULT 150, unload_40gp REAL DEFAULT 280, unload_45hc REAL DEFAULT 330,
    emp_cols TEXT, ts_cols TEXT, export_freq TEXT DEFAULT 'Monthly', export_lang TEXT DEFAULT 'zh',
    created_at TEXT DEFAULT (datetime('now')),
    tax_number TEXT, contact_person TEXT, cooperation_mode TEXT DEFAULT '第三方派遣',
    contact_email TEXT, contact_phone_2 TEXT,
    -- 仓库管理增强: 派遣服务类型
    service_type TEXT DEFAULT '纯派遣',      -- 服务类型 (纯派遣/流程承包/区块承包/整仓承包)
    contract_start_date TEXT,                -- 服务合同开始日期
    contract_end_date TEXT,                  -- 服务合同结束日期
    headcount_quota INTEGER DEFAULT 0,       -- 合同约定人数
    current_headcount INTEGER DEFAULT 0,     -- 当前派遣人数
    updated_at TEXT DEFAULT (datetime('now')));

-- ── NEW: Warehouse Salary Config - 仓库薪资配置表 ──
CREATE TABLE IF NOT EXISTS warehouse_salary_config (
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
    UNIQUE(warehouse_code, grade, position_type));

-- ── Timesheet ──
CREATE TABLE IF NOT EXISTS timesheet (
    id TEXT PRIMARY KEY, employee_id TEXT, employee_name TEXT,
    source TEXT, supplier_id TEXT, biz_line TEXT,
    work_date TEXT, warehouse_code TEXT,
    start_time TEXT, end_time TEXT, hours REAL DEFAULT 0,
    position TEXT, grade TEXT, settle_method TEXT, base_rate REAL DEFAULT 0,
    hourly_pay REAL DEFAULT 0, piece_pay REAL DEFAULT 0,
    perf_bonus REAL DEFAULT 0, other_fee REAL DEFAULT 0,
    ssi_deduct REAL DEFAULT 0, tax_deduct REAL DEFAULT 0, net_pay REAL DEFAULT 0,
    container_no TEXT, container_type TEXT, paper_photo TEXT,
    wh_status TEXT DEFAULT '待班组长审批',
    leader_approver TEXT, leader_approve_time TEXT,
    wh_approver TEXT, wh_approve_time TEXT,
    regional_approver TEXT, regional_approve_time TEXT,
    fin_approver TEXT, fin_approve_time TEXT,
    booked INTEGER DEFAULT 0, notes TEXT,
    dispute_status TEXT, dispute_reason TEXT, dispute_reply TEXT,
    created_at TEXT DEFAULT (datetime('now')), updated_at TEXT DEFAULT (datetime('now')));

-- ── Container Records ──
CREATE TABLE IF NOT EXISTS container_records (
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
    created_at TEXT DEFAULT (datetime('now')));

-- ── Talent Pool ──
CREATE TABLE IF NOT EXISTS talent_pool (
    id TEXT PRIMARY KEY, name TEXT, phone TEXT,
    source TEXT DEFAULT '自有招聘', supplier_id TEXT, target_biz TEXT,
    nationality TEXT, age INTEGER, position_type TEXT,
    languages TEXT, certificates TEXT,
    pool_status TEXT DEFAULT '储备中', file_folder TEXT,
    notes TEXT, created_at TEXT DEFAULT (datetime('now')));

-- ── Schedules ──
CREATE TABLE IF NOT EXISTS schedules (
    id TEXT PRIMARY KEY, employee_id TEXT, employee_name TEXT,
    warehouse_code TEXT, work_date TEXT,
    shift TEXT DEFAULT '白班', start_time TEXT, end_time TEXT,
    position TEXT, biz_line TEXT, status TEXT DEFAULT '已排班',
    actual_in TEXT, actual_out TEXT, notes TEXT,
    created_by TEXT, created_at TEXT DEFAULT (datetime('now')));

-- ── Dispatch Needs ──
CREATE TABLE IF NOT EXISTS dispatch_needs (
    id TEXT PRIMARY KEY, biz_line TEXT, warehouse_code TEXT,
    position TEXT, headcount INTEGER DEFAULT 1,
    start_date TEXT, end_date TEXT, shift TEXT,
    client_settle TEXT, client_rate REAL, matched_count INTEGER DEFAULT 0,
    status TEXT DEFAULT '待处理', priority TEXT DEFAULT '中',
    requester TEXT, notes TEXT, created_at TEXT DEFAULT (datetime('now')));

-- ── Recruit Progress ──
CREATE TABLE IF NOT EXISTS recruit_progress (
    id TEXT PRIMARY KEY, need_id TEXT, candidate_id TEXT,
    source TEXT, supplier_id TEXT, recommend_date TEXT,
    stage TEXT DEFAULT '初筛通过', responsible TEXT,
    status TEXT DEFAULT '进行中', created_at TEXT DEFAULT (datetime('now')));

-- ── Users ──
CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY, password_hash TEXT NOT NULL,
    display_name TEXT, role TEXT DEFAULT 'worker',
    avatar TEXT, color TEXT DEFAULT '#4f6ef7',
    supplier_id TEXT, warehouse_code TEXT, biz_line TEXT, employee_id TEXT,
    active INTEGER DEFAULT 1, created_at TEXT DEFAULT (datetime('now')));

-- ── Permission Overrides ──
CREATE TABLE IF NOT EXISTS permission_overrides (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    role TEXT NOT NULL, module TEXT NOT NULL,
    can_view INTEGER DEFAULT 0, can_create INTEGER DEFAULT 0,
    can_edit INTEGER DEFAULT 0, can_delete INTEGER DEFAULT 0,
    can_export INTEGER DEFAULT 0, can_approve INTEGER DEFAULT 0,
    can_import INTEGER DEFAULT 0,
    hidden_fields TEXT DEFAULT '',
    editable_fields TEXT DEFAULT '',
    updated_by TEXT, updated_at TEXT DEFAULT (datetime('now')),
    UNIQUE(role, module));

-- ── Audit Logs ──
CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT DEFAULT (datetime('now')),
    username TEXT, user_display TEXT,
    action TEXT, target_table TEXT, target_id TEXT,
    old_value TEXT, new_value TEXT, ip_address TEXT);

-- ── Messages ──
CREATE TABLE IF NOT EXISTS messages (
    id TEXT PRIMARY KEY, channel TEXT DEFAULT 'system',
    from_name TEXT, content TEXT, msg_type TEXT DEFAULT 'info',
    matched INTEGER DEFAULT 0, ref_id TEXT,
    timestamp TEXT DEFAULT (datetime('now')));

-- ── Dispatch Transfers ──
CREATE TABLE IF NOT EXISTS dispatch_transfers (
    id TEXT PRIMARY KEY, employee_id TEXT, dispatch_date TEXT,
    start_date TEXT, end_date TEXT, from_wh TEXT, to_wh TEXT,
    transfer_type TEXT DEFAULT '临时支援', biz_line TEXT,
    approver TEXT, reason TEXT, status TEXT DEFAULT '待审批', notes TEXT,
    created_at TEXT DEFAULT (datetime('now')));

-- ── Enterprise Documents - 企业文献库 ──
CREATE TABLE IF NOT EXISTS enterprise_documents (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    category TEXT NOT NULL DEFAULT '通用',
    file_name TEXT,
    file_url TEXT,
    file_type TEXT,
    file_size INTEGER DEFAULT 0,
    description TEXT,
    tags TEXT,
    warehouse_code TEXT,
    uploaded_by TEXT,
    send_to TEXT,
    status TEXT DEFAULT '已发布',
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now')));

-- ── Payslips - 工资条 ──
CREATE TABLE IF NOT EXISTS payslips (
    id TEXT PRIMARY KEY,
    employee_id TEXT NOT NULL,
    employee_name TEXT,
    month TEXT NOT NULL,
    total_hours REAL DEFAULT 0,
    hourly_pay REAL DEFAULT 0,
    piece_pay REAL DEFAULT 0,
    perf_bonus REAL DEFAULT 0,
    other_bonus REAL DEFAULT 0,
    gross_pay REAL DEFAULT 0,
    ssi_deduct REAL DEFAULT 0,
    tax_deduct REAL DEFAULT 0,
    other_deduct REAL DEFAULT 0,
    net_pay REAL DEFAULT 0,
    status TEXT DEFAULT '待确认',
    confirmed_by_employee INTEGER DEFAULT 0,
    confirmed_at TEXT,
    generated_by TEXT,
    notes TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now')));

-- ── Payroll Confirmations - 工资确认流程 ──
CREATE TABLE IF NOT EXISTS payroll_confirmations (
    id TEXT PRIMARY KEY,
    month TEXT NOT NULL,
    step TEXT NOT NULL,
    status TEXT DEFAULT '待审批',
    approver TEXT,
    approve_time TEXT,
    notes TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    UNIQUE(month, step));

-- ============================================================================
-- Indexes for Better Performance and Data Integrity
-- ============================================================================

CREATE UNIQUE INDEX IF NOT EXISTS idx_timesheet_unique ON timesheet(employee_id, work_date, warehouse_code);
CREATE INDEX IF NOT EXISTS idx_timesheet_date ON timesheet(work_date);
CREATE INDEX IF NOT EXISTS idx_employees_status ON employees(status);
CREATE INDEX IF NOT EXISTS idx_users_employee ON users(employee_id);
