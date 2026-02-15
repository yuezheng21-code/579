"""Tests for the HR V6 API endpoints."""
import os
import json
import shutil
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
    # No account should be created by default
    assert "account" not in data


@pytest.mark.asyncio
async def test_create_employee_with_account(auth_headers):
    """Creating an employee with create_account=True should also generate a user account."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.post("/api/employees", headers=auth_headers,
                          json={"name": "权限测试", "grade": "P2", "status": "在职",
                                "primary_wh": "UNA",
                                "create_account": True, "account_role": "wh"})
    assert r.status_code == 200
    data = r.json()
    assert data["ok"] is True
    assert "id" in data
    assert "account" in data
    assert data["account"]["role"] == "wh"
    assert "username" in data["account"]
    assert "password" in data["account"]
    assert len(data["account"]["password"]) == 8

    # Verify the user account was actually created in the database
    employee_id = data["id"]
    db = database.get_db()
    user_row = db.execute("SELECT * FROM users WHERE employee_id=?", (employee_id,)).fetchone()
    db.close()
    assert user_row is not None
    assert user_row["role"] == "wh"

    # Verify employee has_account flag is set
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r2 = await ac.get(f"/api/employees/{employee_id}", headers=auth_headers)
    assert r2.status_code == 200
    assert r2.json()["has_account"] == 1


@pytest.mark.asyncio
async def test_create_employee_with_account_default_role(auth_headers):
    """When create_account=True but no role specified, default to worker."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.post("/api/employees", headers=auth_headers,
                          json={"name": "默认角色", "grade": "P1", "status": "在职",
                                "create_account": True})
    assert r.status_code == 200
    data = r.json()
    assert data["account"]["role"] == "worker"


@pytest.mark.asyncio
async def test_create_employee_with_account_invalid_role(auth_headers):
    """Invalid role should fall back to worker."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.post("/api/employees", headers=auth_headers,
                          json={"name": "无效角色", "grade": "P1", "status": "在职",
                                "create_account": True, "account_role": "invalid_xyz"})
    assert r.status_code == 200
    data = r.json()
    assert data["account"]["role"] == "worker"


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
                          json={"employee_id": "YB-001", "leave_type": "annual",
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
    # Check that grade_title, warehouse_name, supplier_name are linked
    assert "grade_title" in emp
    assert "warehouse_name" in emp
    assert "supplier_name" in emp


@pytest.mark.asyncio
async def test_roster_includes_grade_title(auth_headers):
    """Test roster returns grade_title from grade_levels JOIN."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.get("/api/roster", headers=auth_headers)
    assert r.status_code == 200
    data = r.json()
    # Find YB-001 which has grade=P2
    emp = next((e for e in data if e["id"] == "YB-001"), None)
    assert emp is not None
    assert emp["grade_title"] is not None
    assert emp["warehouse_name"] is not None


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
    """Test roles endpoint returns expanded hierarchy with position-based roles."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.get("/api/roles", headers=auth_headers)
    assert r.status_code == 200
    roles = r.json()
    assert len(roles) >= 22  # expanded from 8 to 22 roles
    role_names = [ro["role"] for ro in roles]
    assert "admin" in role_names
    assert "ceo" in role_names
    # Verify new position-based roles exist
    assert "ops_director" in role_names
    assert "regional_mgr" in role_names
    assert "site_mgr" in role_names
    assert "deputy_mgr" in role_names
    assert "shift_leader" in role_names
    assert "team_leader" in role_names
    assert "fin_director" in role_names
    assert "hr_manager" in role_names
    assert "hr_assistant" in role_names
    assert "hr_specialist" in role_names
    assert "fin_assistant" in role_names
    assert "fin_specialist" in role_names
    assert "admin_assistant" in role_names
    assert "admin_specialist" in role_names
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
    """All modules should have permission_overrides for every role (including new position-based roles)."""
    ALL_MODULES = [
        "dashboard", "employees", "suppliers", "talent", "dispatch", "recruit",
        "timesheet", "settlement", "warehouse", "schedule", "templates",
        "clock", "container", "messages", "analytics", "admin", "logs",
        "grades", "quotation", "files", "leave", "expense", "performance",
        "mypage", "accounts", "whsalary", "safety", "regions"
    ]
    from app import ROLE_HIERARCHY
    ALL_ROLES = list(ROLE_HIERARCHY.keys())
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
            "work_date": "2026-02-10", "warehouse_code": "UNA",
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
            "work_date": "2026-03-05", "warehouse_code": "UNA",
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
            "work_date": "2026-04-05", "warehouse_code": "UNA",
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
            "work_date": "2026-05-05", "warehouse_code": "UNA",
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
            "work_date": "2026-06-05", "warehouse_code": "UNA",
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
            "work_date": "2026-07-05", "warehouse_code": "UNA",
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
            "warehouse_code": "UNA",
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


# ── Tests for Permission Matrix Enhancement and Supplier Worker Visibility ──


@pytest.fixture
def sup_token():
    """Get supplier auth token."""
    from app import make_token
    return make_token("sup1", "sup")


@pytest.fixture
def sup_headers(sup_token):
    """Return headers with supplier token."""
    return {"Authorization": f"Bearer {sup_token}"}


@pytest.fixture
def wh_token():
    """Get warehouse auth token."""
    from app import make_token
    return make_token("wh", "wh")


@pytest.fixture
def wh_headers(wh_token):
    """Return headers with warehouse token."""
    return {"Authorization": f"Bearer {wh_token}"}


@pytest.mark.asyncio
async def test_permission_overrides_have_data_scope():
    """permission_overrides should have data_scope column with correct defaults."""
    db = database.get_db()
    rows = db.execute("SELECT role, module, data_scope FROM permission_overrides").fetchall()
    db.close()
    assert len(rows) > 0
    scope_map = {}
    for r in rows:
        scope_map.setdefault(r["role"], set()).add(r["data_scope"])
    # Check expected data_scope values
    assert "all" in scope_map.get("admin", set())
    assert "all" in scope_map.get("ceo", set())
    assert "own_supplier" in scope_map.get("sup", set())
    assert "own_warehouse" in scope_map.get("wh", set())
    assert "self_only" in scope_map.get("worker", set())


@pytest.mark.asyncio
async def test_supplier_login_includes_supplier_id():
    """Supplier user login should return supplier_id in user info."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.post("/api/login", json={"username": "sup1", "password": "sup123"})
    assert r.status_code == 200
    data = r.json()
    assert data["user"]["role"] == "sup"
    assert data["user"]["supplier_id"] == "SUP-001"


@pytest.mark.asyncio
async def test_wh_login_includes_warehouse_code():
    """Warehouse user login should return warehouse_code in user info."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.post("/api/login", json={"username": "wh", "password": "wh123"})
    assert r.status_code == 200
    data = r.json()
    assert data["user"]["role"] == "wh"
    assert data["user"]["warehouse_code"] == "UNA"


@pytest.mark.asyncio
async def test_supplier_sees_only_own_workers(sup_headers):
    """Supplier user should only see employees from their supplier."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.get("/api/employees", headers=sup_headers)
    assert r.status_code == 200
    employees = r.json()
    # SUP-001 has workers: YB-003, YB-004, YB-009
    assert len(employees) > 0
    for emp in employees:
        assert emp["supplier_id"] == "SUP-001", f"Employee {emp['id']} has supplier_id {emp.get('supplier_id')}, expected SUP-001"


@pytest.mark.asyncio
async def test_supplier_worker_activities(sup_headers):
    """Supplier should be able to see their workers' activities."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.get("/api/supplier/worker-activities", headers=sup_headers)
    assert r.status_code == 200
    data = r.json()
    assert "workers" in data
    assert "timesheet" in data
    assert "leave_requests" in data
    assert "schedules" in data
    assert "summary" in data
    assert data["summary"]["total_workers"] > 0
    # All workers should belong to SUP-001
    for w in data["workers"]:
        assert w["id"] in ["YB-003", "YB-004", "YB-009"]


@pytest.mark.asyncio
async def test_supplier_worker_activities_forbidden_for_worker():
    """Worker role should not access supplier worker activities."""
    from app import make_token
    token = make_token("worker1", "worker")
    headers = {"Authorization": f"Bearer {token}"}
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.get("/api/supplier/worker-activities", headers=headers)
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_admin_can_access_worker_activities(auth_headers):
    """Admin should be able to access supplier worker activities endpoint."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.get("/api/supplier/worker-activities", headers=auth_headers)
    assert r.status_code == 200
    data = r.json()
    assert "workers" in data
    assert "summary" in data


@pytest.mark.asyncio
async def test_permissions_my_includes_data_scope(auth_headers, sup_headers):
    """GET /api/permissions/my should include data_scope and user_context."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        # Admin
        r = await ac.get("/api/permissions/my", headers=auth_headers)
        assert r.status_code == 200
        data = r.json()
        assert "user_context" in data
        for mod, perms in data["permissions"].items():
            assert "data_scope" in perms
            assert perms["data_scope"] == "all"

        # Supplier
        r2 = await ac.get("/api/permissions/my", headers=sup_headers)
        assert r2.status_code == 200
        data2 = r2.json()
        assert "user_context" in data2
        assert data2["user_context"]["supplier_id"] == "SUP-001"


@pytest.mark.asyncio
async def test_permission_check_includes_data_scope(auth_headers):
    """GET /api/permissions/check should include data_scope fields."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.get("/api/permissions/check?module=employees", headers=auth_headers)
    assert r.status_code == 200
    data = r.json()
    assert "data_scope" in data
    assert "scope_grades" in data
    assert "scope_departments" in data
    assert "scope_warehouses" in data


@pytest.mark.asyncio
async def test_permission_update_with_data_scope(auth_headers, wh_headers):
    """Admin should be able to update data_scope in permissions."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.post("/api/permissions/update", headers=auth_headers, json={
            "role": "wh", "module": "employees",
            "can_view": 1, "can_create": 0, "can_edit": 0, "can_delete": 0,
            "can_export": 0, "can_approve": 0, "can_import": 0,
            "data_scope": "own_warehouse",
            "scope_warehouses": "UNA,DHL"
        })
        assert r.status_code == 200

        # Verify the update
        r2 = await ac.get("/api/permissions/check?module=employees", headers=wh_headers)
        assert r2.status_code == 200
        data = r2.json()
        assert data["data_scope"] == "own_warehouse"
        assert data["scope_warehouses"] == "UNA,DHL"


@pytest.mark.asyncio
async def test_supplier_dashboard_scoped(sup_headers):
    """Supplier dashboard should show only their workers' data."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.get("/api/analytics/dashboard", headers=sup_headers)
    assert r.status_code == 200
    data = r.json()
    # SUP-001 has 3 workers (YB-003, YB-004, YB-009)
    assert data["total_emp"] == 3
    assert data["own"] == 0  # All are supplier workers


@pytest.mark.asyncio
async def test_supplier_settlement_scoped(sup_headers):
    """Supplier settlement should only show their own data."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.get("/api/settlement", headers=sup_headers)
    assert r.status_code == 200


@pytest.mark.asyncio
async def test_sup_role_enhanced_permissions():
    """Supplier role should have enhanced view permissions for more modules."""
    db = database.get_db()
    sup_perms = db.execute(
        "SELECT module, can_view FROM permission_overrides WHERE role='sup' AND can_view=1"
    ).fetchall()
    db.close()
    modules_with_view = {p["module"] for p in sup_perms}
    # Supplier should be able to view these modules
    assert "dashboard" in modules_with_view
    assert "employees" in modules_with_view
    assert "timesheet" in modules_with_view
    assert "settlement" in modules_with_view
    assert "schedule" in modules_with_view
    assert "leave" in modules_with_view
    assert "safety" in modules_with_view


# ── New tests for enhanced features ──

@pytest.mark.asyncio
async def test_container_dock_no_and_ratio(auth_headers):
    """Test creating container with dock_no and ratio fields."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.post("/api/containers", headers=auth_headers,
                          json={"container_no": "DOCK-TEST-001", "work_date": "2025-02-01",
                                "warehouse_code": "UNA", "container_type": "40GP",
                                "load_type": "卸柜", "dock_no": "D-03", "ratio": 0.75,
                                "team_size": 3, "start_time": "08:00", "end_time": "10:00"})
        assert r.status_code == 200
        r = await ac.get("/api/containers", headers=auth_headers)
        created = [c for c in r.json() if c.get("container_no") == "DOCK-TEST-001"]
        assert len(created) == 1
        assert created[0]["dock_no"] == "D-03"
        assert created[0]["ratio"] == 0.75


@pytest.mark.asyncio
async def test_template_endpoint(auth_headers):
    """Test downloading import template."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        for table in ["container_records", "schedules", "dispatch_needs", "employees", "suppliers"]:
            r = await ac.get(f"/api/template/{table}", headers=auth_headers)
            assert r.status_code == 200
            data = r.json()
            assert data["table"] == table
            assert "fields" in data
            assert "labels" in data
            assert "sample" in data
            assert len(data["fields"]) == len(data["labels"])


@pytest.mark.asyncio
async def test_template_invalid_table(auth_headers):
    """Test template for invalid table returns error."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.get("/api/template/invalid_table", headers=auth_headers)
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_export_csv_format(auth_headers):
    """Test exporting employees as CSV."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.get("/api/export/employees?fmt=csv", headers=auth_headers)
    assert r.status_code == 200
    assert "text/csv" in r.headers.get("content-type", "")
    content = r.content.decode("utf-8-sig")
    assert len(content) > 0
    lines = content.strip().split("\n")
    assert len(lines) >= 2  # header + at least one data row


@pytest.mark.asyncio
async def test_export_excel_format(auth_headers):
    """Test exporting employees as Excel."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.get("/api/export/employees?fmt=excel", headers=auth_headers)
    assert r.status_code == 200
    assert "ms-excel" in r.headers.get("content-type", "")


@pytest.mark.asyncio
async def test_export_pdf_format(auth_headers):
    """Test exporting employees as text report (PDF replacement)."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.get("/api/export/employees?fmt=pdf", headers=auth_headers)
    assert r.status_code == 200
    assert "text/plain" in r.headers.get("content-type", "")


@pytest.mark.asyncio
async def test_export_container_records(auth_headers):
    """Test exporting container records."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.get("/api/export/container_records", headers=auth_headers)
    assert r.status_code == 200
    data = r.json()
    assert data["table"] == "container_records"
    assert "dock_no" in data["fields"]
    assert "ratio" in data["fields"]


@pytest.mark.asyncio
async def test_export_schedules(auth_headers):
    """Test exporting schedules."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.get("/api/export/schedules", headers=auth_headers)
    assert r.status_code == 200
    data = r.json()
    assert data["table"] == "schedules"


@pytest.mark.asyncio
async def test_export_dispatch_needs(auth_headers):
    """Test exporting dispatch needs."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.get("/api/export/dispatch_needs", headers=auth_headers)
    assert r.status_code == 200
    data = r.json()
    assert data["table"] == "dispatch_needs"


@pytest.mark.asyncio
async def test_import_container_records(auth_headers):
    """Test batch importing container records."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.post("/api/import/container_records", headers=auth_headers,
                          json={"data": [
                              {"container_no": "IMP-CT-001", "work_date": "2025-03-01",
                               "warehouse_code": "UNA", "container_type": "20GP",
                               "dock_no": "D-01", "ratio": 0.5},
                              {"container_no": "IMP-CT-002", "work_date": "2025-03-01",
                               "warehouse_code": "UNA", "container_type": "40GP",
                               "dock_no": "D-02", "ratio": 1.0},
                          ]})
    assert r.status_code == 200
    data = r.json()
    assert data["ok"] is True
    assert data["success"] == 2


@pytest.mark.asyncio
async def test_import_schedules(auth_headers):
    """Test batch importing schedules."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.post("/api/import/schedules", headers=auth_headers,
                          json={"data": [
                              {"employee_id": "YB-001", "employee_name": "张三",
                               "warehouse_code": "UNA", "work_date": "2025-03-15",
                               "shift": "白班"},
                          ]})
    assert r.status_code == 200
    data = r.json()
    assert data["ok"] is True
    assert data["success"] == 1


@pytest.mark.asyncio
async def test_import_dispatch_needs(auth_headers):
    """Test batch importing dispatch needs."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.post("/api/import/dispatch_needs", headers=auth_headers,
                          json={"data": [
                              {"warehouse_code": "UNA", "position": "库内",
                               "headcount": 5, "priority": "高"},
                          ]})
    assert r.status_code == 200
    data = r.json()
    assert data["ok"] is True
    assert data["success"] == 1


@pytest.mark.asyncio
async def test_settlement_warehouse_income(auth_headers):
    """Test settlement warehouse income mode."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.get("/api/settlement?mode=warehouse_income", headers=auth_headers)
    assert r.status_code == 200
    data = r.json()
    assert isinstance(data, list)
    if len(data) > 0:
        assert "warehouse_code" in data[0]
        assert "gross_income" in data[0]
        assert "headcount" in data[0]


@pytest.mark.asyncio
async def test_settlement_worker_expense(auth_headers):
    """Test settlement worker expense mode."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.get("/api/settlement?mode=worker_expense", headers=auth_headers)
    assert r.status_code == 200
    data = r.json()
    assert isinstance(data, list)
    if len(data) > 0:
        assert "employee_id" in data[0]
        assert "warehouse_code" in data[0]
        assert "gross_pay" in data[0]
        assert "net_total" in data[0]


# ── Field-Level Visibility & Editability Tests ──


@pytest.mark.asyncio
async def test_admin_sees_all_employee_fields(auth_headers):
    """Admin (god view) should see all fields including sensitive ones."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.get("/api/employees", headers=auth_headers)
    assert r.status_code == 200
    emps = r.json()
    assert len(emps) > 0
    emp = emps[0]
    # Admin should see all sensitive fields
    for field in ["birth_date", "id_number", "tax_no", "tax_id", "ssn", "iban",
                  "base_salary", "hourly_rate", "health_insurance"]:
        assert field in emp, f"Admin should see field: {field}"


@pytest.mark.asyncio
async def test_wh_hidden_fields_on_employees(wh_headers):
    """Warehouse role should not see sensitive financial/personal fields."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.get("/api/employees", headers=wh_headers)
    assert r.status_code == 200
    emps = r.json()
    assert len(emps) > 0
    emp = emps[0]
    # WH should not see these sensitive fields
    for field in ["tax_no", "tax_id", "ssn", "iban", "base_salary", "hourly_rate", "address"]:
        assert field not in emp, f"WH role should NOT see field: {field}"
    # WH should still see basic work fields
    assert "name" in emp
    assert "position" in emp
    assert "grade" in emp


@pytest.mark.asyncio
async def test_sup_hidden_fields_on_employees(sup_headers):
    """Supplier role should not see sensitive employee fields."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.get("/api/employees", headers=sup_headers)
    assert r.status_code == 200
    emps = r.json()
    assert len(emps) > 0
    emp = emps[0]
    # Supplier should not see financial/personal sensitive fields
    for field in ["tax_no", "tax_id", "ssn", "iban", "base_salary", "hourly_rate", "address"]:
        assert field not in emp, f"Supplier role should NOT see field: {field}"
    # Supplier should still see work-related fields
    assert "name" in emp
    assert "primary_wh" in emp


@pytest.mark.asyncio
async def test_single_employee_hidden_fields(wh_headers):
    """GET /api/employees/{eid} should also respect hidden_fields."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.get("/api/employees/YB-001", headers=wh_headers)
    assert r.status_code == 200
    emp = r.json()
    # WH should not see sensitive fields even for single employee
    for field in ["tax_no", "tax_id", "ssn", "iban"]:
        assert field not in emp, f"WH role should NOT see field: {field} on single employee"
    assert "name" in emp


@pytest.mark.asyncio
async def test_roster_hidden_fields(wh_headers):
    """GET /api/roster should respect hidden_fields filtering."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.get("/api/roster", headers=wh_headers)
    assert r.status_code == 200
    roster = r.json()
    assert len(roster) > 0
    emp = roster[0]
    # WH should not see sensitive fields in roster either
    for field in ["tax_no", "tax_id", "ssn", "iban"]:
        assert field not in emp, f"WH role should NOT see field: {field} in roster"


@pytest.mark.asyncio
async def test_ceo_sees_all_employee_fields(ceo_headers):
    """CEO should see all employee fields (no hidden fields by default)."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.get("/api/employees", headers=ceo_headers)
    assert r.status_code == 200
    emps = r.json()
    assert len(emps) > 0
    emp = emps[0]
    # CEO should see all fields
    for field in ["birth_date", "id_number", "base_salary", "hourly_rate", "iban"]:
        assert field in emp, f"CEO should see field: {field}"


@pytest.mark.asyncio
async def test_admin_can_update_hidden_fields(auth_headers):
    """Admin should be able to configure hidden_fields for a role/module."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        # Update hidden_fields for fin role on employees module
        r = await ac.post("/api/permissions/update", headers=auth_headers,
                          json={"role": "fin", "module": "employees",
                                "can_view": 1, "can_create": 0, "can_edit": 0, "can_delete": 0,
                                "can_export": 1, "can_approve": 0, "can_import": 0,
                                "hidden_fields": "birth_date,id_number,address",
                                "editable_fields": "",
                                "data_scope": "all"})
    assert r.status_code == 200
    assert r.json()["ok"] is True

    # Verify the hidden_fields was saved
    db = database.get_db()
    perm = db.execute("SELECT hidden_fields FROM permission_overrides WHERE role='fin' AND module='employees'").fetchone()
    db.close()
    assert "birth_date" in perm["hidden_fields"]


@pytest.mark.asyncio
async def test_field_definitions_endpoint(auth_headers):
    """Admin should be able to get field definitions for a module."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.get("/api/field-definitions/employees", headers=auth_headers)
    assert r.status_code == 200
    data = r.json()
    assert data["module"] == "employees"
    assert "fields" in data
    fields = data["fields"]
    # Check some sensitive fields are marked
    assert fields["iban"]["sensitive"] is True
    assert fields["tax_id"]["sensitive"] is True
    assert fields["birth_date"]["sensitive"] is True
    # Check non-sensitive fields
    assert fields["name"]["sensitive"] is False
    assert fields["grade"]["sensitive"] is False


@pytest.mark.asyncio
async def test_field_definitions_non_admin_forbidden(ceo_headers):
    """Non-admin roles should not access field definitions."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.get("/api/field-definitions/employees", headers=ceo_headers)
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_hidden_fields_seeded_for_roles():
    """Verify that hidden_fields are properly seeded for sensitive roles."""
    db = database.get_db()
    # Check wh role has hidden fields for employees
    wh_perm = db.execute(
        "SELECT hidden_fields FROM permission_overrides WHERE role='wh' AND module='employees'"
    ).fetchone()
    assert wh_perm is not None
    assert "iban" in wh_perm["hidden_fields"]
    assert "tax_id" in wh_perm["hidden_fields"]
    assert "base_salary" in wh_perm["hidden_fields"]

    # Check worker role has hidden fields for employees
    worker_perm = db.execute(
        "SELECT hidden_fields FROM permission_overrides WHERE role='worker' AND module='employees'"
    ).fetchone()
    assert worker_perm is not None
    assert "iban" in worker_perm["hidden_fields"]
    assert "phone" in worker_perm["hidden_fields"]

    # Check admin has no hidden fields
    admin_perm = db.execute(
        "SELECT hidden_fields FROM permission_overrides WHERE role='admin' AND module='employees'"
    ).fetchone()
    assert admin_perm is not None
    assert admin_perm["hidden_fields"] == ""
    db.close()


@pytest.mark.asyncio
async def test_editable_fields_enforcement(auth_headers):
    """Test that editable_fields are enforced when set for a role."""
    # First, set editable_fields for wh role on employees module
    transport = ASGITransport(app=app)

    # Set editable_fields to restrict what wh can edit (for this test set up a narrow list)
    db = database.get_db()
    db.execute(
        "UPDATE permission_overrides SET can_edit=1, editable_fields='status,position' WHERE role='wh' AND module='employees'"
    )
    db.commit()
    db.close()

    # Try to update employee as wh user - only status and position should be applied
    wh_token = __import__("app").make_token("wh", "wh")
    wh_headers = {"Authorization": f"Bearer {wh_token}"}

    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.put("/api/employees/YB-001", headers=wh_headers,
                         json={"status": "在职", "position": "装卸", "base_salary": 99999})
    assert r.status_code == 200
    # Verify base_salary was NOT changed (enforced by editable_fields)
    # and that allowed fields (status, position) were applied
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.get("/api/employees/YB-001", headers=auth_headers)
    emp = r.json()
    assert emp["base_salary"] != 99999
    assert emp["status"] == "在职"
    assert emp["position"] == "装卸"


# ── Grade-Based Permissions Tests ──


def _link_user_to_employee(username, employee_id):
    """Helper: link a user account to an employee record."""
    db = database.get_db()
    db.execute("UPDATE users SET employee_id=? WHERE username=?", (employee_id, username))
    db.commit()
    db.close()


def _set_employee_grade(employee_id, grade, warehouse=None):
    """Helper: set employee grade and optionally warehouse."""
    db = database.get_db()
    if warehouse:
        db.execute("UPDATE employees SET grade=?, primary_wh=? WHERE id=?", (grade, warehouse, employee_id))
    else:
        db.execute("UPDATE employees SET grade=? WHERE id=?", (grade, employee_id))
    db.commit()
    db.close()


@pytest.mark.asyncio
async def test_warehouse_regions_seeded():
    """Warehouses should have region column populated."""
    db = database.get_db()
    whs = db.execute("SELECT code, region FROM warehouses WHERE region IS NOT NULL AND region != ''").fetchall()
    db.close()
    regions = {w["region"] for w in whs}
    assert "鲁尔西" in regions
    assert "鲁尔东" in regions
    assert "南战区" in regions
    assert len(whs) >= 3  # At least 3 warehouses have regions


@pytest.mark.asyncio
async def test_get_regions_endpoint(auth_headers):
    """GET /api/regions should return regions with warehouses."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.get("/api/regions", headers=auth_headers)
    assert r.status_code == 200
    data = r.json()
    assert len(data) >= 3  # At least 3 regions
    region_names = {d["name"] for d in data}
    assert "鲁尔西" in region_names
    assert "鲁尔东" in region_names
    assert "南战区" in region_names
    # Check 鲁尔西 has UNA and DHL
    ruhr_west = [d for d in data if d["name"] == "鲁尔西"][0]
    wh_codes = {w["code"] for w in ruhr_west["warehouses"]}
    assert "UNA" in wh_codes
    assert "DHL" in wh_codes


@pytest.mark.asyncio
async def test_grade_permissions_endpoint_admin(auth_headers):
    """Admin should get full grade permissions."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.get("/api/permissions/grade", headers=auth_headers)
    assert r.status_code == 200
    data = r.json()
    assert data["data_scope"] == "all"
    assert data["can_dispatch_request"] is True
    assert data["can_transfer_request"] is True
    assert data["salary_scope"] == "all"


@pytest.mark.asyncio
async def test_grade_permissions_endpoint_worker():
    """Worker with P2 grade should have self_only scope."""
    # Link worker1 to YB-001 (P2 grade)
    _link_user_to_employee("worker1", "YB-001")
    from app import make_token
    token = make_token("worker1", "worker")
    headers = {"Authorization": f"Bearer {token}"}
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.get("/api/permissions/grade", headers=headers)
    assert r.status_code == 200
    data = r.json()
    assert data["grade"] == "P2"
    assert data["data_scope"] == "self_only"
    assert data["can_dispatch_request"] is False
    assert data["can_transfer_request"] is False
    assert data["salary_scope"] == "none"


@pytest.mark.asyncio
async def test_p2_worker_sees_only_own_timesheet():
    """P0-P2 worker should only see their own timesheet entries."""
    _link_user_to_employee("worker1", "YB-001")
    from app import make_token
    token = make_token("worker1", "worker")
    headers = {"Authorization": f"Bearer {token}"}
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.get("/api/timesheet", headers=headers)
    assert r.status_code == 200
    data = r.json()
    # All returned timesheet entries should be for YB-001
    for entry in data:
        assert entry["employee_id"] == "YB-001"


@pytest.mark.asyncio
async def test_p2_worker_sees_only_own_schedules():
    """P0-P2 worker should only see their own schedule entries."""
    _link_user_to_employee("worker1", "YB-001")
    from app import make_token
    token = make_token("worker1", "worker")
    headers = {"Authorization": f"Bearer {token}"}
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.get("/api/schedules", headers=headers)
    assert r.status_code == 200
    # Should return only own schedules (or empty)
    data = r.json()
    for entry in data:
        assert entry["employee_id"] == "YB-001"


@pytest.mark.asyncio
async def test_p4_mgr_sees_own_warehouse_timesheet():
    """P4 (组长) with mgr role should see timesheet for their warehouse only."""
    # YB-010 is P4 at EMR warehouse
    _link_user_to_employee("mgr579", "YB-010")
    _set_employee_grade("YB-010", "P4", "EMR")
    from app import make_token
    token = make_token("mgr579", "mgr")
    headers = {"Authorization": f"Bearer {token}"}
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.get("/api/timesheet", headers=headers)
    assert r.status_code == 200
    data = r.json()
    # All entries should be from EMR warehouse
    for entry in data:
        assert entry["warehouse_code"] == "EMR"


@pytest.mark.asyncio
async def test_p5_can_submit_dispatch_request():
    """P5+ should be able to submit personnel requests."""
    _link_user_to_employee("mgr579", "YB-010")
    _set_employee_grade("YB-010", "P5", "EMR")
    from app import make_token
    token = make_token("mgr579", "mgr")
    headers = {"Authorization": f"Bearer {token}"}
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.post("/api/dispatch", headers=headers,
                          json={"warehouse_code": "EMR", "position": "库内", "headcount": 3})
    assert r.status_code == 200
    assert r.json()["ok"] is True


@pytest.mark.asyncio
async def test_p4_cannot_submit_dispatch_request():
    """P4 (below P5) should NOT be able to submit personnel requests."""
    _link_user_to_employee("worker1", "YB-010")
    _set_employee_grade("YB-010", "P4", "EMR")
    from app import make_token
    token = make_token("worker1", "worker")
    headers = {"Authorization": f"Bearer {token}"}
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.post("/api/dispatch", headers=headers,
                          json={"warehouse_code": "EMR", "position": "库内", "headcount": 2})
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_admin_can_always_submit_dispatch(auth_headers):
    """Admin can always submit dispatch requests regardless of grade."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.post("/api/dispatch", headers=auth_headers,
                          json={"warehouse_code": "UNA", "position": "库内", "headcount": 5})
    assert r.status_code == 200
    assert r.json()["ok"] is True


@pytest.mark.asyncio
async def test_p7_can_create_dispatch_transfer():
    """P7 (驻仓经理) should be able to submit warehouse transfer requests."""
    _link_user_to_employee("mgr579", "YB-010")
    _set_employee_grade("YB-010", "P7", "EMR")
    from app import make_token
    token = make_token("mgr579", "mgr")
    headers = {"Authorization": f"Bearer {token}"}
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.post("/api/dispatch-transfers", headers=headers,
                          json={"employee_id": "YB-001", "from_wh": "UNA", "to_wh": "EMR",
                                "transfer_type": "临时支援", "reason": "人力需求"})
    assert r.status_code == 200
    data = r.json()
    assert data["ok"] is True
    assert "id" in data


@pytest.mark.asyncio
async def test_p6_cannot_create_dispatch_transfer():
    """P6 (below P7) should NOT be able to submit warehouse transfer requests."""
    _link_user_to_employee("worker1", "YB-010")
    _set_employee_grade("YB-010", "P6", "EMR")
    from app import make_token
    token = make_token("worker1", "worker")
    headers = {"Authorization": f"Bearer {token}"}
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.post("/api/dispatch-transfers", headers=headers,
                          json={"employee_id": "YB-001", "from_wh": "UNA", "to_wh": "EMR",
                                "transfer_type": "临时支援", "reason": "测试"})
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_dispatch_transfer_creates_audit_log():
    """Creating a dispatch transfer should produce an audit log entry."""
    _link_user_to_employee("mgr579", "YB-010")
    _set_employee_grade("YB-010", "P7", "EMR")
    from app import make_token
    token = make_token("mgr579", "mgr")
    headers = {"Authorization": f"Bearer {token}"}
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.post("/api/dispatch-transfers", headers=headers,
                          json={"employee_id": "YB-002", "from_wh": "DHL", "to_wh": "EMR",
                                "transfer_type": "长期调仓", "reason": "岗位需求"})
    assert r.status_code == 200
    transfer_id = r.json()["id"]
    # Check audit log
    db = database.get_db()
    log = db.execute("SELECT * FROM audit_logs WHERE target_table='dispatch_transfers' AND target_id=?",
                     (transfer_id,)).fetchone()
    db.close()
    assert log is not None
    assert "调仓" in log["new_value"]


@pytest.mark.asyncio
async def test_get_dispatch_transfers(auth_headers):
    """GET /api/dispatch-transfers should return transfer records."""
    # Create a transfer as admin first
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.post("/api/dispatch-transfers", headers=auth_headers,
                          json={"employee_id": "YB-001", "from_wh": "UNA", "to_wh": "DHL",
                                "transfer_type": "临时支援", "reason": "测试"})
    assert r.status_code == 200
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.get("/api/dispatch-transfers", headers=auth_headers)
    assert r.status_code == 200
    data = r.json()
    assert len(data) >= 1


@pytest.mark.asyncio
async def test_p7_salary_own_warehouse_only():
    """P7 should only be able to create salary config for own warehouse."""
    _link_user_to_employee("mgr579", "YB-010")
    _set_employee_grade("YB-010", "P7", "EMR")
    from app import make_token
    token = make_token("mgr579", "mgr")
    headers = {"Authorization": f"Bearer {token}"}
    transport = ASGITransport(app=app)
    # Should succeed for own warehouse (EMR)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.post("/api/warehouse-salary-config", headers=headers,
                          json={"warehouse_code": "EMR", "grade": "P1", "position_type": "测试",
                                "hourly_rate": 12.0})
    assert r.status_code == 200
    # Should fail for other warehouse
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.post("/api/warehouse-salary-config", headers=headers,
                          json={"warehouse_code": "UNA", "grade": "P1", "position_type": "测试",
                                "hourly_rate": 12.0})
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_p8_salary_regional_scope():
    """P8 (区域经理) should be able to modify salary config for regional warehouses only."""
    _link_user_to_employee("mgr579", "YB-010")
    _set_employee_grade("YB-010", "P8", "EMR")  # EMR is in 南战区
    from app import make_token
    token = make_token("mgr579", "mgr")
    headers = {"Authorization": f"Bearer {token}"}
    transport = ASGITransport(app=app)
    # Should succeed for own region (南战区 - EMR is the only one)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.post("/api/warehouse-salary-config", headers=headers,
                          json={"warehouse_code": "EMR", "grade": "P1", "position_type": "区域测试",
                                "hourly_rate": 13.0})
    assert r.status_code == 200
    # Should fail for warehouse in another region (UNA is in 鲁尔西)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.post("/api/warehouse-salary-config", headers=headers,
                          json={"warehouse_code": "UNA", "grade": "P1", "position_type": "区域测试",
                                "hourly_rate": 13.0})
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_p4_salary_suggest_only():
    """P4-P6 should not be able to create/modify salary config (suggest only)."""
    _link_user_to_employee("mgr579", "YB-010")
    _set_employee_grade("YB-010", "P5", "EMR")
    from app import make_token
    token = make_token("mgr579", "mgr")
    headers = {"Authorization": f"Bearer {token}"}
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.post("/api/warehouse-salary-config", headers=headers,
                          json={"warehouse_code": "EMR", "grade": "P1", "position_type": "测试",
                                "hourly_rate": 12.0})
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_p9_salary_all_scope():
    """P9 (运营总监) should be able to modify salary config for all warehouses."""
    _link_user_to_employee("mgr579", "YB-010")
    _set_employee_grade("YB-010", "P9", "EMR")
    from app import make_token
    token = make_token("mgr579", "mgr")
    headers = {"Authorization": f"Bearer {token}"}
    transport = ASGITransport(app=app)
    # Should succeed for any warehouse
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.post("/api/warehouse-salary-config", headers=headers,
                          json={"warehouse_code": "UNA", "grade": "P1", "position_type": "P9测试",
                                "hourly_rate": 14.0})
    assert r.status_code == 200


@pytest.mark.asyncio
async def test_p8_regional_timesheet_scope():
    """P8 (区域经理) should see timesheet for all warehouses in their region."""
    _link_user_to_employee("mgr579", "YB-010")
    _set_employee_grade("YB-010", "P8", "W579")  # W579 is in 鲁尔东 region
    from app import make_token
    token = make_token("mgr579", "mgr")
    headers = {"Authorization": f"Bearer {token}"}
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.get("/api/timesheet", headers=headers)
    assert r.status_code == 200
    data = r.json()
    # Should only see W579 and CMA (both in 鲁尔东)
    allowed_whs = {"W579", "CMA"}
    for entry in data:
        assert entry["warehouse_code"] in allowed_whs, \
            f"P8 in 鲁尔东 should not see timesheet for {entry['warehouse_code']}"


@pytest.mark.asyncio
async def test_dispatch_transfer_validation():
    """POST /api/dispatch-transfers should validate required fields."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        # Missing employee_id
        from app import make_token
        token = make_token("admin", "admin")
        headers = {"Authorization": f"Bearer {token}"}
        r = await ac.post("/api/dispatch-transfers", headers=headers,
                          json={"from_wh": "UNA", "to_wh": "DHL"})
    assert r.status_code == 400

    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        # Missing warehouses
        r = await ac.post("/api/dispatch-transfers", headers=headers,
                          json={"employee_id": "YB-001"})
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_grade_permissions_config():
    """Verify GRADE_PERMISSIONS config covers P0-P9."""
    from app import GRADE_PERMISSIONS
    for grade in ["P0", "P1", "P2", "P3", "P4", "P5", "P6", "P7", "P8", "P9"]:
        assert grade in GRADE_PERMISSIONS
        gp = GRADE_PERMISSIONS[grade]
        assert "data_scope" in gp
        assert "can_dispatch_request" in gp
        assert "can_transfer_request" in gp
        assert "salary_scope" in gp
    # P0-P2 should be self_only
    assert GRADE_PERMISSIONS["P0"]["data_scope"] == "self_only"
    assert GRADE_PERMISSIONS["P2"]["data_scope"] == "self_only"
    # P4-P6 should be own_warehouse
    assert GRADE_PERMISSIONS["P4"]["data_scope"] == "own_warehouse"
    assert GRADE_PERMISSIONS["P6"]["data_scope"] == "own_warehouse"
    # P7 should be own_warehouse
    assert GRADE_PERMISSIONS["P7"]["data_scope"] == "own_warehouse"
    # P8 should be regional
    assert GRADE_PERMISSIONS["P8"]["data_scope"] == "regional"
    # P9 should be all
    assert GRADE_PERMISSIONS["P9"]["data_scope"] == "all"
    # P5+ can dispatch
    assert GRADE_PERMISSIONS["P4"]["can_dispatch_request"] is False
    assert GRADE_PERMISSIONS["P5"]["can_dispatch_request"] is True
    # P7+ can transfer
    assert GRADE_PERMISSIONS["P6"]["can_transfer_request"] is False
    assert GRADE_PERMISSIONS["P7"]["can_transfer_request"] is True


# ── Database Backup & Restore Tests ──


@pytest.mark.asyncio
async def test_backup_create(auth_headers):
    """Admin should be able to create a database backup."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.post("/api/backup", headers=auth_headers)
    assert r.status_code == 200
    data = r.json()
    assert data["ok"] is True
    assert "filename" in data
    assert data["filename"].startswith("backup_")
    assert data["filename"].endswith(".json")
    # Clean up backup file
    shutil.rmtree(database.BACKUP_DIR, ignore_errors=True)


@pytest.mark.asyncio
async def test_backup_list(auth_headers):
    """Admin should be able to list backups."""
    # Create a backup first
    database.backup_database(tag="test_list")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.get("/api/backup/list", headers=auth_headers)
    assert r.status_code == 200
    data = r.json()
    assert isinstance(data, list)
    assert len(data) >= 1
    assert "filename" in data[0]
    assert "total_rows" in data[0]
    # Clean up
    shutil.rmtree(database.BACKUP_DIR, ignore_errors=True)


@pytest.mark.asyncio
async def test_backup_restore(auth_headers):
    """Admin should be able to restore from a backup."""
    # Modify an employee
    db = database.get_db()
    db.execute("UPDATE employees SET phone='+49-BACKUP-TEST' WHERE id='YB-001'")
    db.commit()
    db.close()
    # Create backup with modified data
    filepath = database.backup_database(tag="restore_test")
    filename = os.path.basename(filepath)
    # Reset the employee phone
    db = database.get_db()
    db.execute("UPDATE employees SET phone='+49-RESET' WHERE id='YB-001'")
    db.commit()
    db.close()
    # Restore from backup
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.post("/api/backup/restore", headers=auth_headers,
                          json={"filename": filename})
    assert r.status_code == 200
    data = r.json()
    assert data["ok"] is True
    assert data["total_rows"] > 0
    assert "employees" in data["restored"]
    # Verify restored data
    db = database.get_db()
    emp = db.execute("SELECT phone FROM employees WHERE id='YB-001'").fetchone()
    db.close()
    assert emp["phone"] == "+49-BACKUP-TEST"
    # Clean up
    shutil.rmtree(database.BACKUP_DIR, ignore_errors=True)


@pytest.mark.asyncio
async def test_backup_non_admin_forbidden():
    """Non-admin users should not be able to create/list/restore backups."""
    from app import make_token
    worker_token = make_token("worker1", "worker")
    headers = {"Authorization": f"Bearer {worker_token}"}
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.post("/api/backup", headers=headers)
        assert r.status_code == 403
        r = await ac.get("/api/backup/list", headers=headers)
        assert r.status_code == 403
        r = await ac.post("/api/backup/restore", headers=headers,
                          json={"filename": "test.json"})
        assert r.status_code == 403


@pytest.mark.asyncio
async def test_backup_restore_nonexistent_file(auth_headers):
    """Restoring from a nonexistent backup should return 404."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.post("/api/backup/restore", headers=auth_headers,
                          json={"filename": "nonexistent_backup.json"})
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_backup_restore_path_traversal(auth_headers):
    """Restore should reject filenames with path traversal."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.post("/api/backup/restore", headers=auth_headers,
                          json={"filename": "../etc/passwd"})
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_backup_preserves_data_across_reinit():
    """Backup and restore should preserve employee and timesheet data across DB reinitialization."""
    # Modify employee data
    db = database.get_db()
    db.execute("UPDATE employees SET phone='+49-UPGRADE-TEST' WHERE id='YB-001'")
    db.commit()
    db.close()

    # Simulate upgrade: backup -> reinit -> restore
    backup_path = database.auto_backup_before_upgrade()
    assert backup_path  # Should have created a backup

    # Reinit DB (simulates upgrade)
    if os.path.exists(database.DB_PATH):
        os.remove(database.DB_PATH)
    database.init_db()
    database.seed_data()
    database.ensure_demo_users()

    # Verify data was reset by seed
    db = database.get_db()
    phone = db.execute("SELECT phone FROM employees WHERE id='YB-001'").fetchone()["phone"]
    db.close()
    assert phone != "+49-UPGRADE-TEST"

    # Restore from backup
    summary = database.auto_restore_after_upgrade(backup_path)
    assert summary
    assert summary.get("employees", 0) > 0

    # Verify data is restored
    db = database.get_db()
    phone = db.execute("SELECT phone FROM employees WHERE id='YB-001'").fetchone()["phone"]
    db.close()
    assert phone == "+49-UPGRADE-TEST"

    # Clean up
    shutil.rmtree(database.BACKUP_DIR, ignore_errors=True)


@pytest.mark.asyncio
async def test_backup_database_function():
    """Test backup_database creates valid JSON with all critical tables."""
    filepath = database.backup_database(tag="unit_test")
    assert os.path.exists(filepath)
    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)
    assert "timestamp" in data
    assert "tables" in data
    assert "employees" in data["tables"]
    assert "timesheet" in data["tables"]
    assert "users" in data["tables"]
    assert len(data["tables"]["employees"]) > 0
    # Clean up
    shutil.rmtree(database.BACKUP_DIR, ignore_errors=True)


@pytest.mark.asyncio
async def test_quotation_pdf_no_ids(auth_headers):
    """Test quotation PDF generation rejects empty ids."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.post("/api/quotation-pdf", headers=auth_headers, json={"ids": []})
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_quotation_pdf_not_found(auth_headers):
    """Test quotation PDF returns 404 for non-existent records."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.post("/api/quotation-pdf", headers=auth_headers, json={"ids": ["NONEXIST"]})
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_quotation_pdf_success(auth_headers):
    """Test quotation PDF generation with valid records."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        # Create a quotation record first
        r = await ac.post("/api/quotations", headers=auth_headers, json={
            "client_name": "TestClient",
            "biz_type": "仓储",
            "service_type": "装卸",
            "warehouse_code": "UNA",
            "headcount": 5,
            "base_price": 15.0,
            "final_price": 18.0,
            "total_amount": 900.0,
            "currency": "EUR"
        })
        assert r.status_code == 200
        # Get quotation records to find the ID
        r2 = await ac.get("/api/quotations", headers=auth_headers)
        recs = r2.json()
        assert len(recs) > 0
        qid = recs[0]["id"]
        # Generate PDF
        r3 = await ac.post("/api/quotation-pdf", headers=auth_headers, json={"ids": [qid]})
        assert r3.status_code == 200
        assert r3.headers.get("content-type") == "application/pdf"
        # Verify PDF magic bytes
        assert r3.content[:4] == b"%PDF"


@pytest.mark.asyncio
async def test_quotation_pdf_multiple_records(auth_headers):
    """Test quotation PDF with multiple selected records (组合)."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        # Create two quotation records
        await ac.post("/api/quotations", headers=auth_headers, json={
            "client_name": "ClientA", "biz_type": "仓储", "service_type": "分拣",
            "headcount": 3, "final_price": 20.0, "total_amount": 480.0
        })
        await ac.post("/api/quotations", headers=auth_headers, json={
            "client_name": "ClientB", "biz_type": "物流", "service_type": "配送",
            "headcount": 8, "final_price": 25.0, "total_amount": 1600.0
        })
        recs = (await ac.get("/api/quotations", headers=auth_headers)).json()
        ids = [r["id"] for r in recs]
        assert len(ids) >= 2
        # Generate combined PDF
        r = await ac.post("/api/quotation-pdf", headers=auth_headers, json={"ids": ids})
        assert r.status_code == 200
        assert r.headers.get("content-type") == "application/pdf"
        assert r.content[:4] == b"%PDF"
        assert len(r.content) > 200  # PDF should have meaningful content


@pytest.mark.asyncio
async def test_regions_table_seeded():
    """Regions table should be populated with seed data."""
    db = database.get_db()
    regions = db.execute("SELECT * FROM regions ORDER BY code").fetchall()
    db.close()
    assert len(regions) >= 3
    names = {r["name"] for r in regions}
    assert "鲁尔西" in names
    assert "鲁尔东" in names
    assert "南战区" in names
    # Each region should have a manager assigned
    for r in regions:
        assert r["manager_name"]
        assert r["warehouse_codes"]


@pytest.mark.asyncio
async def test_get_regions_returns_warehouses(auth_headers):
    """GET /api/regions should return regions with enriched warehouse details."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.get("/api/regions", headers=auth_headers)
    assert r.status_code == 200
    data = r.json()
    assert len(data) >= 3
    # Find 鲁尔西 region - should have enriched warehouse objects
    ruhr_west = [d for d in data if d["name"] == "鲁尔西"][0]
    assert "manager_name" in ruhr_west
    assert ruhr_west["manager_name"] != ""
    assert "code" in ruhr_west  # Region has its own code
    assert len(ruhr_west["warehouses"]) >= 2


@pytest.mark.asyncio
async def test_create_region(auth_headers):
    """POST /api/regions should create a new region."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.post("/api/regions", headers=auth_headers, json={
            "code": "REG-TEST",
            "name": "测试大区",
            "description": "测试用大区",
            "warehouse_codes": "",
            "status": "启用"
        })
    assert r.status_code == 200
    assert r.json()["ok"] is True
    assert r.json()["code"] == "REG-TEST"


@pytest.mark.asyncio
async def test_create_region_validation(auth_headers):
    """POST /api/regions should fail without code or name."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.post("/api/regions", headers=auth_headers, json={})
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_update_region(auth_headers):
    """PUT /api/regions/{code} should update a region."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.put("/api/regions/REG-RUHRW", headers=auth_headers, json={
            "description": "更新描述"
        })
    assert r.status_code == 200
    assert r.json()["ok"] is True


@pytest.mark.asyncio
async def test_update_region_not_found(auth_headers):
    """PUT /api/regions/{code} should return 404 for non-existent region."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.put("/api/regions/NONEXISTENT", headers=auth_headers, json={
            "description": "test"
        })
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_delete_region(auth_headers):
    """DELETE /api/regions/{code} should delete a region."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        # First create a region to delete
        await ac.post("/api/regions", headers=auth_headers, json={
            "code": "REG-DEL",
            "name": "待删除大区",
            "warehouse_codes": ""
        })
        r = await ac.delete("/api/regions/REG-DEL", headers=auth_headers)
    assert r.status_code == 200
    assert r.json()["ok"] is True


@pytest.mark.asyncio
async def test_delete_region_not_found(auth_headers):
    """DELETE /api/regions/{code} should return 404 for non-existent region."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.delete("/api/regions/NONEXISTENT", headers=auth_headers)
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_region_manager_permissions_endpoint(auth_headers):
    """GET /api/regions/permissions should return P8 permission details."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.get("/api/regions/permissions", headers=auth_headers)
    assert r.status_code == 200
    data = r.json()
    assert data["grade"] == "P8"
    assert data["data_scope"] == "regional"
    assert data["salary_scope"] == "regional"
    assert data["can_dispatch_request"] is True
    assert data["can_transfer_request"] is True
    assert "permissions_detail" in data
    assert len(data["permissions_detail"]) > 0
    assert "approval_flow" in data


@pytest.mark.asyncio
async def test_region_worker_cannot_create():
    """Worker role should not be able to create regions."""
    from app import make_token
    worker_token = make_token("worker1", "worker")
    headers = {"Authorization": f"Bearer {worker_token}"}
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.post("/api/regions", headers=headers, json={
            "code": "REG-FAIL",
            "name": "不允许"
        })
    assert r.status_code == 403


# ── Employee Roster Association Tests ──

@pytest.mark.asyncio
async def test_employees_include_joined_fields(auth_headers):
    """Test that /api/employees returns warehouse_name, supplier_name, and grade_title."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.get("/api/employees", headers=auth_headers)
    assert r.status_code == 200
    data = r.json()
    assert len(data) > 0
    # Find an employee with a known warehouse (YB-001 has primary_wh=UNA from seed data)
    emp = next((e for e in data if e["id"] == "YB-001"), None)
    assert emp is not None
    assert "warehouse_name" in emp
    assert "supplier_name" in emp
    assert "grade_title" in emp
    # YB-001 has primary_wh=UNA, so warehouse_name should be resolved
    assert emp["warehouse_name"] is not None


@pytest.mark.asyncio
async def test_employee_detail_includes_joined_fields(auth_headers):
    """Test that /api/employees/{eid} returns warehouse_name, supplier_name, and grade_title."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.get("/api/employees/YB-001", headers=auth_headers)
    assert r.status_code == 200
    emp = r.json()
    assert "warehouse_name" in emp
    assert "supplier_name" in emp
    assert "grade_title" in emp
    assert emp["warehouse_name"] is not None


# ── Bug Fix Verification Tests ──

@pytest.mark.asyncio
async def test_timesheet_invalid_date_format(auth_headers):
    """Test that creating timesheet with invalid date returns 400 instead of crashing."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.post("/api/timesheet", headers=auth_headers,
                          json={"employee_id": "YB-001", "work_date": "not-a-date",
                                "warehouse_code": "UNA", "hours": 8})
    assert r.status_code == 400
    assert "not-a-date" in r.json()["detail"]


@pytest.mark.asyncio
async def test_timesheet_malformed_date(auth_headers):
    """Test that creating timesheet with malformed date returns 400."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.post("/api/timesheet", headers=auth_headers,
                          json={"employee_id": "YB-001", "work_date": "2026-13-45",
                                "warehouse_code": "UNA", "hours": 8})
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_account_generate_nonexistent_employee(auth_headers):
    """Test generating account for nonexistent employee returns 404 without leaking DB connection."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.post("/api/accounts/generate", headers=auth_headers,
                          json={"employee_id": "NONEXIST-999"})
    assert r.status_code == 404


# ── Job Positions Tests ──


@pytest.mark.asyncio
async def test_get_job_positions(auth_headers):
    """Test that job positions are seeded and returned."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.get("/api/job-positions", headers=auth_headers)
    assert r.status_code == 200
    positions = r.json()
    assert len(positions) >= 18  # 18 seeded positions
    codes = [p["code"] for p in positions]
    assert "OPS-DIR" in codes
    assert "REG-MGR" in codes
    assert "SITE-MGR" in codes
    assert "TEAM-LDR" in codes
    assert "FIN-DIR" in codes
    assert "HR-MGR" in codes
    assert "WORKER" in codes


@pytest.mark.asyncio
async def test_get_job_position_detail(auth_headers):
    """Test getting a single job position by code."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.get("/api/job-positions/OPS-DIR", headers=auth_headers)
    assert r.status_code == 200
    pos = r.json()
    assert pos["code"] == "OPS-DIR"
    assert pos["title_zh"] == "运营总监"
    assert pos["default_role"] == "ops_director"
    assert pos["grade_code"] == "P9"
    assert pos["data_scope"] == "all"


@pytest.mark.asyncio
async def test_create_job_position(auth_headers):
    """Admin can create a new job position."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.post("/api/job-positions", headers=auth_headers,
                          json={"code": "TEST-POS", "title_zh": "测试岗位",
                                "category": "运营", "default_role": "worker"})
    assert r.status_code == 200
    assert r.json()["ok"] is True
    assert r.json()["code"] == "TEST-POS"


@pytest.mark.asyncio
async def test_update_job_position(auth_headers):
    """Admin can update a job position."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.put("/api/job-positions/WORKER", headers=auth_headers,
                         json={"description": "Updated description"})
    assert r.status_code == 200
    assert r.json()["ok"] is True


@pytest.mark.asyncio
async def test_delete_job_position(auth_headers):
    """Admin can delete a job position."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        # Create first, then delete
        await ac.post("/api/job-positions", headers=auth_headers,
                      json={"code": "DEL-POS", "title_zh": "待删岗位"})
        r = await ac.delete("/api/job-positions/DEL-POS", headers=auth_headers)
    assert r.status_code == 200
    assert r.json()["ok"] is True


@pytest.mark.asyncio
async def test_non_admin_cannot_create_job_position():
    """Non-admin users cannot create job positions."""
    from app import make_token
    worker_token = make_token("worker1", "worker")
    headers = {"Authorization": f"Bearer {worker_token}"}
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.post("/api/job-positions", headers=headers,
                          json={"code": "FAIL-POS", "title_zh": "不允许"})
    assert r.status_code == 403


# ── Position-Based Role Permissions Tests ──


@pytest.mark.asyncio
async def test_ops_director_has_all_data_scope():
    """Ops director should have 'all' data scope."""
    from app import make_token
    token = make_token("ops_dir", "ops_director")
    headers = {"Authorization": f"Bearer {token}"}
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.get("/api/permissions/my", headers=headers)
    assert r.status_code == 200
    data = r.json()
    assert data["role"] == "ops_director"
    assert data["role_level"] == 85
    # Ops director should view all modules
    emp_perm = data["permissions"].get("employees", {})
    assert emp_perm.get("can_view") == 1
    assert emp_perm.get("data_scope") == "all"


@pytest.mark.asyncio
async def test_regional_mgr_has_regional_scope():
    """Regional manager should have 'regional' data scope."""
    from app import make_token
    token = make_token("reg_mgr", "regional_mgr")
    headers = {"Authorization": f"Bearer {token}"}
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.get("/api/permissions/my", headers=headers)
    assert r.status_code == 200
    data = r.json()
    assert data["role"] == "regional_mgr"
    assert data["role_level"] == 80
    emp_perm = data["permissions"].get("employees", {})
    assert emp_perm.get("data_scope") == "regional"


@pytest.mark.asyncio
async def test_site_mgr_has_own_warehouse_scope():
    """Site manager should have 'own_warehouse' data scope."""
    from app import make_token
    token = make_token("site_mgr1", "site_mgr")
    headers = {"Authorization": f"Bearer {token}"}
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.get("/api/permissions/my", headers=headers)
    assert r.status_code == 200
    data = r.json()
    assert data["role"] == "site_mgr"
    assert data["role_level"] == 75
    emp_perm = data["permissions"].get("employees", {})
    assert emp_perm.get("data_scope") == "own_warehouse"


@pytest.mark.asyncio
async def test_site_mgr_hidden_fields():
    """Site manager should have tax/iban hidden from employee records."""
    db = database.get_db()
    perm = db.execute(
        "SELECT hidden_fields FROM permission_overrides WHERE role='site_mgr' AND module='employees'"
    ).fetchone()
    db.close()
    assert perm is not None
    assert "iban" in perm["hidden_fields"]
    assert "tax_no" in perm["hidden_fields"]


@pytest.mark.asyncio
async def test_team_leader_restricted_view():
    """Team leader should have restricted view (no salary/sensitive fields)."""
    db = database.get_db()
    perm = db.execute(
        "SELECT hidden_fields, data_scope FROM permission_overrides WHERE role='team_leader' AND module='employees'"
    ).fetchone()
    db.close()
    assert perm is not None
    assert "base_salary" in perm["hidden_fields"]
    assert "iban" in perm["hidden_fields"]
    assert perm["data_scope"] == "own_warehouse"


@pytest.mark.asyncio
async def test_hr_manager_sees_all_employee_data():
    """HR manager should see all employee data (no hidden fields)."""
    db = database.get_db()
    perm = db.execute(
        "SELECT hidden_fields, data_scope FROM permission_overrides WHERE role='hr_manager' AND module='employees'"
    ).fetchone()
    db.close()
    assert perm is not None
    assert perm["hidden_fields"] == ""
    assert perm["data_scope"] == "all"


@pytest.mark.asyncio
async def test_fin_director_limited_employee_fields():
    """Finance director should have limited employee field visibility."""
    db = database.get_db()
    perm = db.execute(
        "SELECT hidden_fields FROM permission_overrides WHERE role='fin_director' AND module='employees'"
    ).fetchone()
    db.close()
    assert perm is not None
    assert "emergency_contact" in perm["hidden_fields"]


@pytest.mark.asyncio
async def test_job_positions_linked_to_grades():
    """Job positions should be linked to grade codes."""
    transport = ASGITransport(app=app)
    from app import make_token
    token = make_token("admin", "admin")
    headers = {"Authorization": f"Bearer {token}"}
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.get("/api/job-positions", headers=headers)
    assert r.status_code == 200
    positions = r.json()
    # Verify positions link to proper grades
    ops_dir = next(p for p in positions if p["code"] == "OPS-DIR")
    assert ops_dir["grade_code"] == "P9"
    assert ops_dir["category"] == "运营"
    reg_mgr = next(p for p in positions if p["code"] == "REG-MGR")
    assert reg_mgr["grade_code"] == "P8"
    hr_mgr = next(p for p in positions if p["code"] == "HR-MGR")
    assert hr_mgr["grade_code"] == "M4"
    assert hr_mgr["category"] == "人事"


@pytest.mark.asyncio
async def test_new_roles_have_correct_hierarchy():
    """Verify new position-based roles have correct hierarchy levels in ROLE_HIERARCHY."""
    from app import ROLE_HIERARCHY
    assert ROLE_HIERARCHY["ops_director"] == 85
    assert ROLE_HIERARCHY["regional_mgr"] == 80
    assert ROLE_HIERARCHY["site_mgr"] == 75
    assert ROLE_HIERARCHY["deputy_mgr"] == 70
    assert ROLE_HIERARCHY["shift_leader"] == 65
    assert ROLE_HIERARCHY["team_leader"] == 60
    assert ROLE_HIERARCHY["hr_manager"] == 60
    assert ROLE_HIERARCHY["fin_director"] == 55
    # Ops director should be between CEO and regional_mgr
    assert ROLE_HIERARCHY["ceo"] > ROLE_HIERARCHY["ops_director"]
    assert ROLE_HIERARCHY["ops_director"] > ROLE_HIERARCHY["regional_mgr"]


@pytest.mark.asyncio
async def test_settlement_endpoint(auth_headers):
    """Test settlement endpoint works with try/finally DB handling."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        for mode in ["own", "supplier", "warehouse_income", "worker_expense", "default"]:
            r = await ac.get(f"/api/settlement?mode={mode}", headers=auth_headers)
            assert r.status_code == 200
            assert isinstance(r.json(), list)


@pytest.mark.asyncio
async def test_payroll_summary_default_month(auth_headers):
    """Test payroll summary with default month parameter."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.get("/api/payroll-summary", headers=auth_headers)
    assert r.status_code == 200
    assert isinstance(r.json(), list)
