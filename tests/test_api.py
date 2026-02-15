"""Tests for the HR V6 API endpoints."""
import os
import pytest
from httpx import AsyncClient, ASGITransport

# Use a separate test database
os.environ["DATABASE_URL"] = ""

from app import app  # noqa: E402
import database  # noqa: E402


@pytest.fixture(autouse=True)
def setup_db():
    """Initialize a fresh test database for each test."""
    # Remove any existing test DB
    if os.path.exists(database.DB_PATH):
        os.remove(database.DB_PATH)
    database.init_db()
    database.seed_data()
    database.ensure_demo_users()
    yield
    if os.path.exists(database.DB_PATH):
        os.remove(database.DB_PATH)


@pytest.fixture
def admin_token():
    """Get admin auth token."""
    from app import make_token
    return make_token("admin", "admin")


@pytest.fixture
def auth_headers(admin_token):
    """Return headers with admin token."""
    return {"Authorization": f"Bearer {admin_token}"}


@pytest.mark.asyncio
async def test_health_check():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


@pytest.mark.asyncio
async def test_login_success():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.post("/api/login", json={"username": "admin", "password": "admin123"})
    assert r.status_code == 200
    data = r.json()
    assert "token" in data
    assert data["user"]["role"] == "admin"


@pytest.mark.asyncio
async def test_login_failure():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.post("/api/login", json={"username": "admin", "password": "wrong"})
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_get_employees(auth_headers):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.get("/api/employees", headers=auth_headers)
    assert r.status_code == 200
    assert isinstance(r.json(), list)
    assert len(r.json()) > 0


@pytest.mark.asyncio
async def test_create_employee_validation(auth_headers):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        # Missing name should fail
        r = await ac.post("/api/employees", headers=auth_headers, json={})
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_create_employee_success(auth_headers):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.post("/api/employees", headers=auth_headers,
                          json={"name": "测试员工", "grade": "P1", "status": "在职"})
    assert r.status_code == 200
    data = r.json()
    assert data["ok"] is True
    assert "id" in data


@pytest.mark.asyncio
async def test_create_supplier_validation(auth_headers):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.post("/api/suppliers", headers=auth_headers, json={})
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_create_supplier_success(auth_headers):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.post("/api/suppliers", headers=auth_headers,
                          json={"name": "测试供应商"})
    assert r.status_code == 200
    assert r.json()["ok"] is True


@pytest.mark.asyncio
async def test_create_promotion_validation(auth_headers):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.post("/api/promotions", headers=auth_headers, json={})
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_create_promotion_success(auth_headers):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.post("/api/promotions", headers=auth_headers,
                          json={"employee_id": "YB-001", "current_grade": "P1", "target_grade": "P2"})
    assert r.status_code == 200
    assert r.json()["ok"] is True


@pytest.mark.asyncio
async def test_create_bonus_validation(auth_headers):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.post("/api/bonuses", headers=auth_headers, json={})
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_create_performance_validation(auth_headers):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.post("/api/performance", headers=auth_headers, json={})
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_create_quotation_validation(auth_headers):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.post("/api/quotations", headers=auth_headers, json={})
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_create_leave_request_validation(auth_headers):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        # Missing required fields
        r = await ac.post("/api/leave-requests", headers=auth_headers, json={})
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_create_leave_request_success(auth_headers):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.post("/api/leave-requests", headers=auth_headers,
                          json={"employee_id": "YB-001", "leave_type": "AL",
                                "start_date": "2026-03-01", "end_date": "2026-03-02", "days": 2})
    assert r.status_code == 200
    assert r.json()["ok"] is True


@pytest.mark.asyncio
async def test_create_expense_validation(auth_headers):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.post("/api/expenses", headers=auth_headers, json={})
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_create_expense_success(auth_headers):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.post("/api/expenses", headers=auth_headers,
                          json={"employee_id": "YB-001", "amount": 100, "claim_type": "差旅"})
    assert r.status_code == 200
    assert r.json()["ok"] is True


@pytest.mark.asyncio
async def test_create_file_record_validation(auth_headers):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.post("/api/files", headers=auth_headers, json={})
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_create_grade_evaluation_validation(auth_headers):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.post("/api/grade-evaluations", headers=auth_headers, json={})
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_create_timesheet_validation(auth_headers):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.post("/api/timesheet", headers=auth_headers, json={})
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_create_wh_salary_config_validation(auth_headers):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.post("/api/warehouse-salary-config", headers=auth_headers, json={})
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_dashboard(auth_headers):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.get("/api/analytics/dashboard", headers=auth_headers)
    assert r.status_code == 200
    data = r.json()
    assert "total_emp" in data
    assert "pending_leave" in data


@pytest.mark.asyncio
async def test_get_grades(auth_headers):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.get("/api/grades", headers=auth_headers)
    assert r.status_code == 200
    assert isinstance(r.json(), list)
    assert len(r.json()) > 0


@pytest.mark.asyncio
async def test_get_warehouses(auth_headers):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.get("/api/warehouses", headers=auth_headers)
    assert r.status_code == 200
    assert isinstance(r.json(), list)


@pytest.mark.asyncio
async def test_get_leave_types(auth_headers):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.get("/api/leave-types", headers=auth_headers)
    assert r.status_code == 200
    assert isinstance(r.json(), list)


@pytest.mark.asyncio
async def test_unauthorized_access():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.get("/api/employees")
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_permissions_update_validation(auth_headers):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.post("/api/permissions/update", headers=auth_headers, json={})
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_update_employee(auth_headers):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        # First get an employee
        r = await ac.get("/api/employees", headers=auth_headers)
        employees = r.json()
        assert len(employees) > 0
        eid = employees[0]["id"]

        # Update the employee
        r = await ac.put(f"/api/employees/{eid}", headers=auth_headers,
                         json={"phone": "123456789"})
    assert r.status_code == 200
    assert r.json()["ok"] is True


@pytest.mark.asyncio
async def test_audit_logging(auth_headers):
    """Test that create operations produce audit log entries."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        # Create an employee
        await ac.post("/api/employees", headers=auth_headers,
                      json={"name": "审计测试"})

        # Check audit logs
        r = await ac.get("/api/logs", headers=auth_headers)
    assert r.status_code == 200
    logs = r.json()
    # Should have at least one audit entry for the create
    create_logs = [l for l in logs if l.get("action") == "create" and l.get("target_table") == "employees"]
    assert len(create_logs) > 0


# ── Warehouse Management Tests ──

@pytest.mark.asyncio
async def test_create_warehouse_validation(auth_headers):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.post("/api/warehouses", headers=auth_headers, json={})
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_create_warehouse_success(auth_headers):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.post("/api/warehouses", headers=auth_headers,
                          json={"code": "TEST", "name": "测试仓库", "address": "Test Addr",
                                "tax_number": "DE999888777", "contact_person": "测试负责人",
                                "cooperation_mode": "自营"})
    assert r.status_code == 200
    assert r.json()["ok"] is True
    assert r.json()["code"] == "TEST"


@pytest.mark.asyncio
async def test_update_warehouse(auth_headers):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.put("/api/warehouses/UNA", headers=auth_headers,
                         json={"tax_number": "DE111111111", "contact_person": "新负责人",
                               "cooperation_mode": "外包"})
    assert r.status_code == 200
    assert r.json()["ok"] is True


@pytest.mark.asyncio
async def test_warehouse_new_fields(auth_headers):
    """Test that warehouses include the new fields."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.get("/api/warehouses", headers=auth_headers)
    assert r.status_code == 200
    whs = r.json()
    assert len(whs) > 0
    wh = whs[0]
    assert "tax_number" in wh
    assert "contact_person" in wh
    assert "cooperation_mode" in wh


# ── Enterprise Documents Tests ──

@pytest.mark.asyncio
async def test_create_enterprise_doc_validation(auth_headers):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.post("/api/enterprise-docs", headers=auth_headers, json={})
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_create_enterprise_doc_success(auth_headers):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.post("/api/enterprise-docs", headers=auth_headers,
                          json={"title": "测试安全手册", "category": "安全培训",
                                "description": "测试文档", "send_to": "全员"})
    assert r.status_code == 200
    assert r.json()["ok"] is True
    assert "id" in r.json()


@pytest.mark.asyncio
async def test_get_enterprise_docs(auth_headers):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.get("/api/enterprise-docs", headers=auth_headers)
    assert r.status_code == 200
    assert isinstance(r.json(), list)
    assert len(r.json()) > 0


@pytest.mark.asyncio
async def test_get_enterprise_docs_by_category(auth_headers):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.get("/api/enterprise-docs?category=安全培训", headers=auth_headers)
    assert r.status_code == 200
    docs = r.json()
    assert len(docs) > 0
    assert all(d["category"] == "安全培训" for d in docs)


@pytest.mark.asyncio
async def test_update_enterprise_doc(auth_headers):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.put("/api/enterprise-docs/ED-001", headers=auth_headers,
                         json={"title": "更新的安全手册", "status": "草稿"})
    assert r.status_code == 200
    assert r.json()["ok"] is True


# ── Roster (花名册) Tests ──

@pytest.mark.asyncio
async def test_get_roster(auth_headers):
    """Test roster endpoint returns employees with joined supplier and warehouse info."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.get("/api/roster", headers=auth_headers)
    assert r.status_code == 200
    data = r.json()
    assert isinstance(data, list)
    assert len(data) > 0
    # Check new roster fields exist
    emp = data[0]
    assert "contract_type" in emp
    assert "dispatch_type" in emp
    assert "emergency_contact" in emp


@pytest.mark.asyncio
async def test_get_roster_filter_by_dispatch_type(auth_headers):
    """Test roster filtering by dispatch_type."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.get("/api/roster?dispatch_type=纯派遣", headers=auth_headers)
    assert r.status_code == 200
    data = r.json()
    assert isinstance(data, list)
    for emp in data:
        assert emp["dispatch_type"] == "纯派遣"


@pytest.mark.asyncio
async def test_get_roster_filter_by_warehouse(auth_headers):
    """Test roster filtering by warehouse_code."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.get("/api/roster?warehouse_code=UNA", headers=auth_headers)
    assert r.status_code == 200
    data = r.json()
    assert isinstance(data, list)
    assert len(data) > 0


@pytest.mark.asyncio
async def test_get_roster_stats(auth_headers):
    """Test roster statistics endpoint."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.get("/api/roster/stats", headers=auth_headers)
    assert r.status_code == 200
    data = r.json()
    assert "by_dispatch_type" in data
    assert "by_contract_type" in data
    assert "by_source" in data
    assert "by_nationality" in data
    assert "contract_expiring_soon" in data
    assert "work_permit_expiring_soon" in data


@pytest.mark.asyncio
async def test_employee_new_roster_fields(auth_headers):
    """Test that employees include new roster fields."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.get("/api/employees/YB-001", headers=auth_headers)
    assert r.status_code == 200
    emp = r.json()
    assert emp["contract_type"] == "劳动合同"
    assert emp["dispatch_type"] == "整仓承包"
    assert emp["emergency_contact"] == "李梅"
    assert emp["emergency_phone"] == "+49-176-9001"


@pytest.mark.asyncio
async def test_create_employee_with_roster_fields(auth_headers):
    """Test creating employee with new roster fields."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.post("/api/employees", headers=auth_headers,
                          json={"name": "花名册测试", "contract_type": "劳务合同",
                                "dispatch_type": "纯派遣", "emergency_contact": "张三",
                                "emergency_phone": "123456"})
    assert r.status_code == 200
    assert r.json()["ok"] is True


# ── Supplier Enhancement Tests ──

@pytest.mark.asyncio
async def test_update_supplier(auth_headers):
    """Test updating a supplier."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.put("/api/suppliers/SUP-001", headers=auth_headers,
                         json={"rating": "A+", "max_headcount": 60,
                               "bank_name": "Sparkasse", "service_scope": "全德地区"})
    assert r.status_code == 200
    assert r.json()["ok"] is True


@pytest.mark.asyncio
async def test_get_supplier_detail(auth_headers):
    """Test getting a single supplier."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.get("/api/suppliers/SUP-001", headers=auth_headers)
    assert r.status_code == 200
    sup = r.json()
    assert sup["name"] == "德信人力"
    assert "service_scope" in sup
    assert "dispatch_types" in sup
    assert "bank_name" in sup
    assert "max_headcount" in sup


@pytest.mark.asyncio
async def test_get_supplier_not_found(auth_headers):
    """Test getting a non-existent supplier returns 404."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.get("/api/suppliers/NONEXIST", headers=auth_headers)
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_supplier_new_fields(auth_headers):
    """Test that suppliers include new fields."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.get("/api/suppliers", headers=auth_headers)
    assert r.status_code == 200
    sups = r.json()
    assert len(sups) > 0
    sup = sups[0]
    assert "service_scope" in sup
    assert "dispatch_types" in sup
    assert "bank_name" in sup
    assert "bank_account" in sup
    assert "max_headcount" in sup
    assert "current_headcount" in sup


# ── Warehouse Enhancement Tests ──

@pytest.mark.asyncio
async def test_warehouse_service_type_fields(auth_headers):
    """Test that warehouses include new service_type fields."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.get("/api/warehouses", headers=auth_headers)
    assert r.status_code == 200
    whs = r.json()
    assert len(whs) > 0
    wh = whs[0]
    assert "service_type" in wh
    assert "contract_start_date" in wh
    assert "contract_end_date" in wh
    assert "headcount_quota" in wh
    assert "current_headcount" in wh
    assert wh["cooperation_mode"] == "第三方派遣"


@pytest.mark.asyncio
async def test_warehouse_service_types_present(auth_headers):
    """Test that all four dispatch service types are represented in seed data."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.get("/api/warehouses", headers=auth_headers)
    assert r.status_code == 200
    whs = r.json()
    service_types = {wh["service_type"] for wh in whs}
    assert "纯派遣" in service_types
    assert "流程承包" in service_types
    assert "区块承包" in service_types
    assert "整仓承包" in service_types


@pytest.mark.asyncio
async def test_create_warehouse_with_service_type(auth_headers):
    """Test creating warehouse with service_type."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.post("/api/warehouses", headers=auth_headers,
                          json={"code": "NEW1", "name": "新仓库",
                                "service_type": "整仓承包",
                                "cooperation_mode": "第三方派遣",
                                "headcount_quota": 30,
                                "contract_start_date": "2026-01-01",
                                "contract_end_date": "2027-12-31"})
    assert r.status_code == 200
    assert r.json()["ok"] is True


@pytest.mark.asyncio
async def test_dashboard_includes_service_type_dist(auth_headers):
    """Test that dashboard includes service_type and dispatch_type distributions."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.get("/api/analytics/dashboard", headers=auth_headers)
    assert r.status_code == 200
    data = r.json()
    assert "service_type_dist" in data
    assert "dispatch_type_dist" in data
    assert len(data["service_type_dist"]) > 0
    assert len(data["dispatch_type_dist"]) > 0


# ── CEO Role and Enhanced Permissions Tests ──

@pytest.fixture
def ceo_token():
    """Get CEO auth token."""
    from app import make_token
    return make_token("ceo_wb", "ceo")


@pytest.fixture
def ceo_headers(ceo_token):
    """Return headers with CEO token."""
    return {"Authorization": f"Bearer {ceo_token}"}


@pytest.fixture
def worker_token():
    """Get worker auth token."""
    from app import make_token
    return make_token("worker1", "worker")


@pytest.fixture
def worker_headers(worker_token):
    """Return headers with worker token."""
    return {"Authorization": f"Bearer {worker_token}"}


@pytest.mark.asyncio
async def test_ceo_login():
    """Test CEO accounts (王博 and 袁梁毅) can login."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.post("/api/login", json={"username": "ceo_wb", "password": "ceo123"})
    assert r.status_code == 200
    data = r.json()
    assert data["user"]["role"] == "ceo"
    assert "王博" in data["user"]["display_name"]


@pytest.mark.asyncio
async def test_ceo_login_yly():
    """Test CEO 袁梁毅 can login."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.post("/api/login", json={"username": "ceo_yly", "password": "ceo123"})
    assert r.status_code == 200
    data = r.json()
    assert data["user"]["role"] == "ceo"
    assert "袁梁毅" in data["user"]["display_name"]


@pytest.mark.asyncio
async def test_get_roles(auth_headers):
    """Test roles endpoint returns hierarchy."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.get("/api/roles", headers=auth_headers)
    assert r.status_code == 200
    roles = r.json()
    assert len(roles) >= 8
    role_names = [ro["role"] for ro in roles]
    assert "admin" in role_names
    assert "ceo" in role_names
    # admin level should be highest
    admin_role = next(ro for ro in roles if ro["role"] == "admin")
    ceo_role = next(ro for ro in roles if ro["role"] == "ceo")
    assert admin_role["level"] > ceo_role["level"]


@pytest.mark.asyncio
async def test_admin_god_view_permissions(auth_headers):
    """Admin has god view - all permissions for every module."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.get("/api/permissions/my", headers=auth_headers)
    assert r.status_code == 200
    data = r.json()
    assert data["is_admin"] is True
    assert data["role_level"] == 100
    # Admin should have all permissions on all modules
    for module, perms in data["permissions"].items():
        assert perms["can_view"] == 1
        assert perms["can_create"] == 1
        assert perms["can_edit"] == 1
        assert perms["can_delete"] == 1
        assert perms["can_export"] == 1
        assert perms["can_import"] == 1


@pytest.mark.asyncio
async def test_ceo_permissions(ceo_headers):
    """CEO has near-full access but is below admin."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.get("/api/permissions/my", headers=ceo_headers)
    assert r.status_code == 200
    data = r.json()
    assert data["is_ceo"] is True
    assert data["role_level"] == 90
    # CEO should be able to view all modules
    for module, perms in data["permissions"].items():
        assert perms["can_view"] == 1


@pytest.mark.asyncio
async def test_permission_check_module(auth_headers):
    """Test check single module permission."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.get("/api/permissions/check?module=employees", headers=auth_headers)
    assert r.status_code == 200
    data = r.json()
    assert data["role"] == "admin"
    assert data["can_view"] == 1
    assert data["can_import"] == 1


@pytest.mark.asyncio
async def test_worker_restricted_permissions(worker_headers):
    """Worker should have limited permissions."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.get("/api/permissions/my", headers=worker_headers)
    assert r.status_code == 200
    data = r.json()
    assert data["role"] == "worker"
    assert data["role_level"] == 10
    # Worker should not have admin module access
    admin_perm = data["permissions"].get("admin", {})
    assert admin_perm.get("can_view", 0) == 0


@pytest.mark.asyncio
async def test_permissions_include_can_import(auth_headers):
    """Test that permission_overrides includes can_import field."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.get("/api/permissions", headers=auth_headers)
    assert r.status_code == 200
    perms = r.json()
    assert len(perms) > 0
    # Check that can_import field exists
    assert "can_import" in perms[0]


@pytest.mark.asyncio
async def test_only_admin_can_update_permissions(ceo_headers):
    """Only admin can update permissions, CEO cannot."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.post("/api/permissions/update", headers=ceo_headers,
                          json={"role": "worker", "module": "employees", "can_view": 1})
    assert r.status_code == 403


# ── Import / Export Tests ──

@pytest.mark.asyncio
async def test_export_employees(auth_headers):
    """Test exporting employees."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.get("/api/export/employees", headers=auth_headers)
    assert r.status_code == 200
    data = r.json()
    assert data["table"] == "employees"
    assert "fields" in data
    assert "data" in data
    assert data["count"] > 0
    # Check that data contains expected fields
    assert "name" in data["fields"]
    assert "grade" in data["fields"]


@pytest.mark.asyncio
async def test_export_suppliers(auth_headers):
    """Test exporting suppliers."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.get("/api/export/suppliers", headers=auth_headers)
    assert r.status_code == 200
    data = r.json()
    assert data["table"] == "suppliers"
    assert data["count"] > 0


@pytest.mark.asyncio
async def test_export_timesheet(auth_headers):
    """Test exporting timesheet."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.get("/api/export/timesheet", headers=auth_headers)
    assert r.status_code == 200
    data = r.json()
    assert data["table"] == "timesheet"
    assert data["count"] > 0


@pytest.mark.asyncio
async def test_export_invalid_table(auth_headers):
    """Test exporting invalid table returns error."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.get("/api/export/invalid_table", headers=auth_headers)
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_export_permission_denied(worker_headers):
    """Worker cannot export employees."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.get("/api/export/employees", headers=worker_headers)
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_import_employees(auth_headers):
    """Test batch importing employees."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.post("/api/import/employees", headers=auth_headers,
                          json={"data": [
                              {"name": "导入测试员工1", "grade": "P1", "status": "在职"},
                              {"name": "导入测试员工2", "grade": "P2", "status": "在职"},
                          ]})
    assert r.status_code == 200
    data = r.json()
    assert data["ok"] is True
    assert data["success"] == 2
    assert data["total"] == 2
    assert len(data["errors"]) == 0


@pytest.mark.asyncio
async def test_import_empty_data(auth_headers):
    """Test importing empty data returns error."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.post("/api/import/employees", headers=auth_headers,
                          json={"data": []})
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_import_validation_errors(auth_headers):
    """Test import with invalid records tracks errors."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.post("/api/import/employees", headers=auth_headers,
                          json={"data": [
                              {"name": "有效员工", "grade": "P1"},
                              {"grade": "P1"},  # Missing name
                          ]})
    assert r.status_code == 200
    data = r.json()
    assert data["success"] == 1
    assert len(data["errors"]) == 1


@pytest.mark.asyncio
async def test_import_permission_denied(worker_headers):
    """Worker cannot import employees."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.post("/api/import/employees", headers=worker_headers,
                          json={"data": [{"name": "test"}]})
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_import_upsert(auth_headers):
    """Test import with existing ID updates instead of duplicating."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        # Import with existing employee ID
        r = await ac.post("/api/import/employees", headers=auth_headers,
                          json={"data": [
                              {"id": "YB-001", "name": "张三更新", "phone": "999999"},
                          ]})
    assert r.status_code == 200
    data = r.json()
    assert data["success"] == 1


# ── CRUD for Remaining Tables ──

@pytest.mark.asyncio
async def test_update_timesheet(auth_headers):
    """Test updating a timesheet record."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        # Get a timesheet record first
        r = await ac.get("/api/timesheet", headers=auth_headers)
        ts = r.json()
        assert len(ts) > 0
        tid = ts[0]["id"]
        r = await ac.put(f"/api/timesheet/{tid}", headers=auth_headers,
                         json={"notes": "测试更新"})
    assert r.status_code == 200
    assert r.json()["ok"] is True


@pytest.mark.asyncio
async def test_create_and_update_container(auth_headers):
    """Test creating and updating a container record."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        # Create a container record
        r = await ac.post("/api/containers", headers=auth_headers,
                          json={"container_no": "TEST-CT-001", "work_date": "2025-01-15",
                                "warehouse_code": "UNA", "container_type": "40GP",
                                "load_type": "卸柜", "team_size": 2,
                                "start_time": "08:00", "end_time": "09:30"})
        assert r.status_code == 200
        assert r.json()["ok"] is True

        # Get containers to find the one we just created
        r = await ac.get("/api/containers", headers=auth_headers)
        assert r.status_code == 200
        containers = r.json()
        created = [c for c in containers if c.get("container_no") == "TEST-CT-001"]
        assert len(created) == 1
        cid = created[0]["id"]
        assert created[0]["duration_minutes"] == 90

        # Update the container record
        r = await ac.put(f"/api/containers/{cid}", headers=auth_headers,
                         json={"team_size": 4, "notes": "测试更新"})
        assert r.status_code == 200
        assert r.json()["ok"] is True

        # Verify the update
        r = await ac.get("/api/containers", headers=auth_headers)
        containers = r.json()
        updated = [c for c in containers if c["id"] == cid]
        assert len(updated) == 1
        assert updated[0]["team_size"] == 4
        assert updated[0]["notes"] == "测试更新"


@pytest.mark.asyncio
async def test_update_container_with_time_recalculation(auth_headers):
    """Test that updating container times recalculates duration."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        # Create a container record
        r = await ac.post("/api/containers", headers=auth_headers,
                          json={"container_no": "TEST-CT-002", "work_date": "2025-01-16",
                                "warehouse_code": "UNA", "container_type": "20GP",
                                "load_type": "装柜", "team_size": 3,
                                "start_time": "10:00", "end_time": "11:00"})
        assert r.status_code == 200

        r = await ac.get("/api/containers", headers=auth_headers)
        created = [c for c in r.json() if c.get("container_no") == "TEST-CT-002"]
        cid = created[0]["id"]

        # Update with new times
        r = await ac.put(f"/api/containers/{cid}", headers=auth_headers,
                         json={"start_time": "08:00", "end_time": "10:30"})
        assert r.status_code == 200

        r = await ac.get("/api/containers", headers=auth_headers)
        updated = [c for c in r.json() if c["id"] == cid]
        assert updated[0]["duration_minutes"] == 150


@pytest.mark.asyncio
async def test_create_talent(auth_headers):
    """Test creating a talent pool record."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.post("/api/talent", headers=auth_headers,
                          json={"name": "测试人才", "position_type": "库内"})
    assert r.status_code == 200
    assert r.json()["ok"] is True
    assert "id" in r.json()


@pytest.mark.asyncio
async def test_create_talent_validation(auth_headers):
    """Test creating talent with missing name fails."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.post("/api/talent", headers=auth_headers, json={})
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_create_dispatch(auth_headers):
    """Test creating a dispatch need."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.post("/api/dispatch", headers=auth_headers,
                          json={"warehouse_code": "UNA", "headcount": 5, "position": "库内"})
    assert r.status_code == 200
    assert r.json()["ok"] is True


@pytest.mark.asyncio
async def test_create_dispatch_validation(auth_headers):
    """Test creating dispatch with missing warehouse fails."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.post("/api/dispatch", headers=auth_headers, json={})
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_create_schedule(auth_headers):
    """Test creating a schedule."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.post("/api/schedules", headers=auth_headers,
                          json={"employee_id": "YB-001", "work_date": "2026-03-01",
                                "warehouse_code": "UNA", "shift": "白班"})
    assert r.status_code == 200
    assert r.json()["ok"] is True


@pytest.mark.asyncio
async def test_create_schedule_validation(auth_headers):
    """Test creating schedule with missing fields fails."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.post("/api/schedules", headers=auth_headers, json={})
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_delete_record_admin(auth_headers):
    """Admin can delete records (soft-delete)."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        # Create a talent record first
        r = await ac.post("/api/talent", headers=auth_headers,
                          json={"name": "删除测试"})
        tid = r.json()["id"]
        # Delete it
        r = await ac.delete(f"/api/talent_pool/{tid}", headers=auth_headers)
    assert r.status_code == 200
    assert r.json()["ok"] is True


@pytest.mark.asyncio
async def test_delete_record_worker_denied(worker_headers):
    """Worker cannot delete records."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.delete("/api/employees/YB-001", headers=worker_headers)
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_delete_invalid_table(auth_headers):
    """Cannot delete from non-allowed tables."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.delete("/api/audit_logs/1", headers=auth_headers)
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_admin_can_edit_all_modules(auth_headers):
    """Admin (system administrator) should have can_edit=1 for ALL modules."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.get("/api/permissions/my", headers=auth_headers)
    assert r.status_code == 200
    data = r.json()
    assert data["is_admin"] is True
    for module, perms in data["permissions"].items():
        assert perms["can_edit"] == 1, f"Admin missing can_edit on module: {module}"


@pytest.mark.asyncio
async def test_admin_can_update_permission_matrix(auth_headers):
    """Admin should be able to update permissions for other roles via the permission matrix."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        # Update worker's employees module to allow editing
        r = await ac.post("/api/permissions/update", headers=auth_headers,
                          json={"role": "worker", "module": "employees",
                                "can_view": 1, "can_create": 0, "can_edit": 1,
                                "can_delete": 0, "can_export": 0, "can_approve": 0, "can_import": 0})
        assert r.status_code == 200
        assert r.json()["ok"] is True
        # Verify the update was applied
        r2 = await ac.get("/api/permissions", headers=auth_headers)
        assert r2.status_code == 200
        perms = r2.json()
        worker_emp = [p for p in perms if p["role"] == "worker" and p["module"] == "employees"]
        assert len(worker_emp) == 1
        assert worker_emp[0]["can_edit"] == 1
        assert worker_emp[0]["can_view"] == 1


@pytest.mark.asyncio
async def test_admin_check_edit_permission_per_module(auth_headers):
    """Admin should have can_edit=1 when checking specific modules."""
    transport = ASGITransport(app=app)
    modules_to_check = ["employees", "suppliers", "admin", "settlement", "warehouse"]
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        for mod in modules_to_check:
            r = await ac.get(f"/api/permissions/check?module={mod}", headers=auth_headers)
            assert r.status_code == 200
            data = r.json()
            assert data["can_edit"] == 1, f"Admin missing can_edit on check for module: {mod}"


@pytest.mark.asyncio
async def test_all_modules_have_permissions_seeded():
    """All 27 modules should have permission_overrides for every role."""
    ALL_MODULES = [
        "dashboard", "employees", "suppliers", "talent", "dispatch", "recruit",
        "timesheet", "settlement", "warehouse", "schedule", "templates",
        "clock", "container", "messages", "analytics", "admin", "logs",
        "grades", "quotation", "files", "leave", "expense", "performance",
        "mypage", "accounts", "whsalary", "safety"
    ]
    ALL_ROLES = ["admin", "ceo", "hr", "wh", "fin", "sup", "mgr", "worker"]
    db = database.get_db()
    for role in ALL_ROLES:
        for mod in ALL_MODULES:
            row = db.execute(
                "SELECT * FROM permission_overrides WHERE role=? AND module=?",
                (role, mod)
            ).fetchone()
            assert row is not None, f"Missing permission_overrides for role={role}, module={mod}"
    db.close()


# ── New Tests: Multi-level Approval, Payslips, Disputes, Payroll Preview ──


@pytest.mark.asyncio
async def test_employees_have_work_hours_per_week(auth_headers):
    """Employee records should include work_hours_per_week field."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.get("/api/employees", headers=auth_headers)
    assert r.status_code == 200
    emps = r.json()
    assert len(emps) > 0
    assert "work_hours_per_week" in emps[0]


@pytest.mark.asyncio
async def test_multi_level_timesheet_approval(auth_headers):
    """Timesheet batch-approve should support leader/wh/regional/fin types."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        # Create a timesheet entry first
        emps = (await ac.get("/api/employees", headers=auth_headers)).json()
        emp = emps[0]
        ts_data = {
            "employee_id": emp["id"], "employee_name": emp["name"],
            "work_date": "2026-02-10", "warehouse_code": "WH001",
            "start_time": "08:00", "end_time": "16:00", "hours": 8,
            "position": "库内", "grade": emp.get("grade", "P1"),
            "base_rate": 12, "hourly_pay": 96
        }
        r = await ac.post("/api/timesheet", json=ts_data, headers=auth_headers)
        assert r.status_code == 200

        # Get the created timesheet ID
        all_ts = (await ac.get("/api/timesheet", headers=auth_headers)).json()
        ts_entry = [t for t in all_ts if t["employee_id"] == emp["id"] and t["work_date"] == "2026-02-10"]
        assert len(ts_entry) > 0
        ts_id = ts_entry[0]["id"]

        # Step 1: leader approval
        r = await ac.post("/api/timesheet/batch-approve",
                          json={"ids": [ts_id], "type": "leader"}, headers=auth_headers)
        assert r.status_code == 200
        all_ts = (await ac.get("/api/timesheet", headers=auth_headers)).json()
        ts = [t for t in all_ts if t["id"] == ts_id][0]
        assert ts["wh_status"] == "已班组长审批"

        # Step 2: warehouse manager approval
        r = await ac.post("/api/timesheet/batch-approve",
                          json={"ids": [ts_id], "type": "wh"}, headers=auth_headers)
        assert r.status_code == 200
        all_ts = (await ac.get("/api/timesheet", headers=auth_headers)).json()
        ts = [t for t in all_ts if t["id"] == ts_id][0]
        assert ts["wh_status"] == "已仓库审批"

        # Step 3: regional manager approval
        r = await ac.post("/api/timesheet/batch-approve",
                          json={"ids": [ts_id], "type": "regional"}, headers=auth_headers)
        assert r.status_code == 200
        all_ts = (await ac.get("/api/timesheet", headers=auth_headers)).json()
        ts = [t for t in all_ts if t["id"] == ts_id][0]
        assert ts["wh_status"] == "已区域审批"

        # Step 4: finance confirmation
        r = await ac.post("/api/timesheet/batch-approve",
                          json={"ids": [ts_id], "type": "fin"}, headers=auth_headers)
        assert r.status_code == 200
        all_ts = (await ac.get("/api/timesheet", headers=auth_headers)).json()
        ts = [t for t in all_ts if t["id"] == ts_id][0]
        assert ts["wh_status"] == "已入账"


@pytest.mark.asyncio
async def test_payslip_generate_and_list(auth_headers):
    """Generate payslips from timesheet and list them."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        # Create timesheet entry
        emps = (await ac.get("/api/employees", headers=auth_headers)).json()
        emp = emps[0]
        await ac.post("/api/timesheet", json={
            "employee_id": emp["id"], "employee_name": emp["name"],
            "work_date": "2026-03-05", "warehouse_code": "WH001",
            "start_time": "08:00", "end_time": "16:00", "hours": 8,
            "position": "库内", "grade": "P1", "base_rate": 12,
            "hourly_pay": 96, "net_pay": 80
        }, headers=auth_headers)

        # Generate payslips for the month
        r = await ac.post("/api/payslips/generate",
                          json={"month": "2026-03"}, headers=auth_headers)
        assert r.status_code == 200
        assert r.json()["count"] >= 1

        # List payslips
        r = await ac.get("/api/payslips?month=2026-03", headers=auth_headers)
        assert r.status_code == 200
        payslips = r.json()
        assert len(payslips) >= 1
        assert payslips[0]["status"] == "待确认"


@pytest.mark.asyncio
async def test_payslip_confirm(auth_headers):
    """Employee can confirm a payslip."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        emps = (await ac.get("/api/employees", headers=auth_headers)).json()
        emp = emps[0]
        await ac.post("/api/timesheet", json={
            "employee_id": emp["id"], "employee_name": emp["name"],
            "work_date": "2026-04-05", "warehouse_code": "WH001",
            "start_time": "08:00", "end_time": "16:00", "hours": 8,
            "position": "库内", "grade": "P1", "base_rate": 12,
            "hourly_pay": 96, "net_pay": 80
        }, headers=auth_headers)
        await ac.post("/api/payslips/generate",
                      json={"month": "2026-04"}, headers=auth_headers)
        payslips = (await ac.get("/api/payslips?month=2026-04", headers=auth_headers)).json()
        pid = payslips[0]["id"]

        r = await ac.post(f"/api/payslips/{pid}/confirm", headers=auth_headers)
        assert r.status_code == 200

        updated = (await ac.get("/api/payslips?month=2026-04", headers=auth_headers)).json()
        confirmed = [p for p in updated if p["id"] == pid]
        assert confirmed[0]["status"] == "已确认"
        assert confirmed[0]["confirmed_by_employee"] == 1


@pytest.mark.asyncio
async def test_payslip_dispute(auth_headers):
    """Employee can dispute a payslip."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        emps = (await ac.get("/api/employees", headers=auth_headers)).json()
        emp = emps[0]
        await ac.post("/api/timesheet", json={
            "employee_id": emp["id"], "employee_name": emp["name"],
            "work_date": "2026-05-05", "warehouse_code": "WH001",
            "start_time": "08:00", "end_time": "16:00", "hours": 8,
            "position": "库内", "grade": "P1", "base_rate": 12,
            "hourly_pay": 96, "net_pay": 80
        }, headers=auth_headers)
        await ac.post("/api/payslips/generate",
                      json={"month": "2026-05"}, headers=auth_headers)
        payslips = (await ac.get("/api/payslips?month=2026-05", headers=auth_headers)).json()
        pid = payslips[0]["id"]

        r = await ac.post(f"/api/payslips/{pid}/dispute",
                          json={"reason": "工时计算有误"}, headers=auth_headers)
        assert r.status_code == 200

        updated = (await ac.get("/api/payslips?month=2026-05", headers=auth_headers)).json()
        disputed = [p for p in updated if p["id"] == pid]
        assert disputed[0]["status"] == "申诉中"


@pytest.mark.asyncio
async def test_timesheet_dispute_and_reply(auth_headers):
    """Employee can dispute a timesheet entry and manager can reply."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        emps = (await ac.get("/api/employees", headers=auth_headers)).json()
        emp = emps[0]
        r = await ac.post("/api/timesheet", json={
            "employee_id": emp["id"], "employee_name": emp["name"],
            "work_date": "2026-06-05", "warehouse_code": "WH001",
            "start_time": "08:00", "end_time": "16:00", "hours": 8,
            "position": "库内", "grade": "P1", "base_rate": 12,
            "hourly_pay": 96, "net_pay": 80
        }, headers=auth_headers)
        assert r.status_code == 200
        all_ts = (await ac.get("/api/timesheet", headers=auth_headers)).json()
        ts_entry = [t for t in all_ts if t["employee_id"] == emp["id"] and t["work_date"] == "2026-06-05"]
        ts_id = ts_entry[0]["id"]

        # File dispute
        r = await ac.post(f"/api/timesheet/{ts_id}/dispute",
                          json={"reason": "实际工作9小时"}, headers=auth_headers)
        assert r.status_code == 200
        all_ts = (await ac.get("/api/timesheet", headers=auth_headers)).json()
        ts = [t for t in all_ts if t["id"] == ts_id][0]
        assert ts["dispute_status"] == "申诉中"

        # Manager reply
        r = await ac.post(f"/api/timesheet/{ts_id}/dispute-reply",
                          json={"reply": "已核实并调整", "status": "已处理"}, headers=auth_headers)
        assert r.status_code == 200
        all_ts = (await ac.get("/api/timesheet", headers=auth_headers)).json()
        ts = [t for t in all_ts if t["id"] == ts_id][0]
        assert ts["dispute_status"] == "已处理"
        assert ts["dispute_reply"] == "已核实并调整"


@pytest.mark.asyncio
async def test_payroll_preview(auth_headers):
    """Payroll preview should return employee summary and confirmation status."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        emps = (await ac.get("/api/employees", headers=auth_headers)).json()
        emp = emps[0]
        await ac.post("/api/timesheet", json={
            "employee_id": emp["id"], "employee_name": emp["name"],
            "work_date": "2026-07-05", "warehouse_code": "WH001",
            "start_time": "08:00", "end_time": "16:00", "hours": 8,
            "position": "库内", "grade": "P1", "base_rate": 12,
            "hourly_pay": 96, "net_pay": 80
        }, headers=auth_headers)

        r = await ac.get("/api/payroll-preview?month=2026-07", headers=auth_headers)
        assert r.status_code == 200
        data = r.json()
        assert "month" in data
        assert "employees" in data
        assert "confirmations" in data
        assert "total_count" in data
        assert data["total_count"] >= 1


@pytest.mark.asyncio
async def test_payroll_confirmation_flow(auth_headers):
    """Payroll confirmation should support 4-step approval."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        for step in ["leader", "wh_manager", "regional_manager", "finance"]:
            r = await ac.post("/api/payroll-confirmations",
                              json={"month": "2026-08", "step": step},
                              headers=auth_headers)
            assert r.status_code == 200
            assert r.json()["step"] == step

        # Verify all steps are approved
        r = await ac.get("/api/payroll-confirmations?month=2026-08", headers=auth_headers)
        assert r.status_code == 200
        confirmations = r.json()
        assert len(confirmations) == 4
        for c in confirmations:
            assert c["status"] == "已审批"


@pytest.mark.asyncio
async def test_payroll_confirmation_invalid_step(auth_headers):
    """Invalid approval step should return 400."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.post("/api/payroll-confirmations",
                          json={"month": "2026-08", "step": "invalid_step"},
                          headers=auth_headers)
        assert r.status_code == 400


# ── Tests: Safety Incidents, Org Chart, Employee Registration, Compliance ──

@pytest.mark.asyncio
async def test_safety_incidents_crud(auth_headers):
    """Create, list, and update safety incidents."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        # Create
        r = await ac.post("/api/safety-incidents", json={
            "incident_type": "安全事件",
            "severity": "严重",
            "warehouse_code": "UNA",
            "incident_date": "2026-02-10",
            "description": "叉车碰撞货架",
            "involved_employees": "YB-001"
        }, headers=auth_headers)
        assert r.status_code == 200
        assert r.json()["ok"] is True
        sid = r.json()["id"]

        # List
        r = await ac.get("/api/safety-incidents", headers=auth_headers)
        assert r.status_code == 200
        incidents = r.json()
        assert len(incidents) >= 1

        # Update
        r = await ac.put(f"/api/safety-incidents/{sid}", json={
            "status": "已解决",
            "corrective_action": "加装防护栏"
        }, headers=auth_headers)
        assert r.status_code == 200


@pytest.mark.asyncio
async def test_safety_incident_missing_description(auth_headers):
    """Safety incident without description should return 400."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.post("/api/safety-incidents", json={
            "incident_type": "安全事件",
            "severity": "一般"
        }, headers=auth_headers)
        assert r.status_code == 400


@pytest.mark.asyncio
async def test_org_chart(auth_headers):
    """Org chart should return hierarchy levels and warehouse groups."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.get("/api/org-chart", headers=auth_headers)
        assert r.status_code == 200
        data = r.json()
        assert "levels" in data
        assert "by_warehouse" in data
        assert "total" in data
        assert data["total"] > 0
        assert len(data["levels"]) == 7  # P9, P8, P7, P5/P6, P4, P2/P3, P0/P1


@pytest.mark.asyncio
async def test_employee_self_registration():
    """Self-registration should create employee without auth."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.post("/api/employee-register", json={
            "name": "TestUser",
            "gender": "男",
            "nationality": "CN",
            "phone": "+49-176-1234",
            "email": "test@example.com",
            "tax_class": "1",
            "health_insurance": "TK",
            "iban": "DE89370400440532013000"
        })
        assert r.status_code == 200
        data = r.json()
        assert data["ok"] is True
        assert data["id"].startswith("YB-")


@pytest.mark.asyncio
async def test_employee_self_registration_missing_name():
    """Self-registration without name should return 400."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.post("/api/employee-register", json={
            "gender": "男",
            "nationality": "CN"
        })
        assert r.status_code == 400


@pytest.mark.asyncio
async def test_id_naming_rules(auth_headers):
    """ID naming rules should be readable and updatable."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        # Get rules
        r = await ac.get("/api/id-naming-rules", headers=auth_headers)
        assert r.status_code == 200
        rules = r.json()
        assert len(rules) >= 1
        assert rules[0]["prefix"] == "YB"

        # Update rules
        r = await ac.put("/api/id-naming-rules", json={
            "prefix": "EMP",
            "separator": "-",
            "next_number": 100,
            "padding": 4,
            "description": "新规则"
        }, headers=auth_headers)
        assert r.status_code == 200


@pytest.mark.asyncio
async def test_compliance_check(auth_headers):
    """Compliance check should return violation data."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.get("/api/compliance/work-hours?month=2026-02", headers=auth_headers)
        assert r.status_code == 200
        data = r.json()
        assert "month" in data
        assert "daily_violations" in data
        assert "weekly_violations" in data
        assert "compliant" in data


@pytest.mark.asyncio
async def test_timesheet_compliance_daily_limit(auth_headers):
    """Timesheet creation with >10h should be rejected."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        emps = (await ac.get("/api/employees", headers=auth_headers)).json()
        emp = emps[0]
        r = await ac.post("/api/timesheet", json={
            "employee_id": emp["id"],
            "employee_name": emp["name"],
            "work_date": "2026-03-20",
            "warehouse_code": "WH001",
            "start_time": "06:00",
            "end_time": "17:00",
            "hours": 11,
            "position": "库内",
            "grade": "P1",
            "base_rate": 12,
            "hourly_pay": 132
        }, headers=auth_headers)
        assert r.status_code == 400
        assert "10" in r.json()["detail"]
