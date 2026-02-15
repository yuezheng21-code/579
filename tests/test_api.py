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
    assert all(d["category"] == "安全培训" for d in docs)


@pytest.mark.asyncio
async def test_update_enterprise_doc(auth_headers):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.put("/api/enterprise-docs/ED-001", headers=auth_headers,
                         json={"title": "更新的安全手册", "status": "草稿"})
    assert r.status_code == 200
    assert r.json()["ok"] is True
