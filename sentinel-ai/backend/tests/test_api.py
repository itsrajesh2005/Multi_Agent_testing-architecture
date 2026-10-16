"""
SentinelAI — Automated Test Suite

Tests cover: health, auth, RBAC, assessments, scope validation,
agent workflow, findings, reports, audit logging, and demo mode.

All tests use an in-memory SQLite database and mocked Gemini responses.
No real API keys or external services are required.
"""

from __future__ import annotations

import os
import json
import pytest
import asyncio
from datetime import datetime, timezone
from unittest.mock import patch, AsyncMock, MagicMock

# Force test settings BEFORE any app imports
os.environ["DATABASE_URL"] = "sqlite:///./test_sentinel.db"
os.environ["JWT_SECRET_KEY"] = "test-jwt-secret-key-for-testing-only-32chars"
os.environ["APP_SECRET_KEY"] = "test-app-secret-key-for-testing-only-32chars"
os.environ["DEMO_MODE"] = "true"
os.environ["REQUIRE_HUMAN_APPROVAL"] = "true"

from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

from app.main import app
from app.db.database import Base, get_db
from app.models import (
    User, UserRole, AuditAction, AuditLog,
    Assessment, AssessmentScope, AssessmentType,
    ExecutionMode, AssessmentStatus,
)
from app.security.auth import hash_password, verify_password, create_access_token

# ── Test Database Setup ──────────────────────────────────────────────

SQLALCHEMY_TEST_URL = "sqlite:///./test_sentinel.db"
test_engine = create_engine(SQLALCHEMY_TEST_URL, connect_args={"check_same_thread": False})

@event.listens_for(test_engine, "connect")
def _set_sqlite_pragma(dbapi_connection, connection_record):
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON;")
    cursor.close()

TestSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)


def override_get_db():
    db = TestSessionLocal()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db


# ── Fixtures ─────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def setup_db():
    """Create tables before each test, drop after."""
    Base.metadata.create_all(bind=test_engine)
    db = TestSessionLocal()
    # Seed test users
    for u_data in [
        {"username": "admin", "email": "admin@test.local", "password": "admin123", "role": UserRole.ADMIN},
        {"username": "analyst", "email": "analyst@test.local", "password": "analyst123", "role": UserRole.ANALYST},
        {"username": "viewer", "email": "viewer@test.local", "password": "viewer123", "role": UserRole.VIEWER},
    ]:
        existing = db.query(User).filter(User.username == u_data["username"]).first()
        if not existing:
            user = User(
                username=u_data["username"],
                email=u_data["email"],
                hashed_password=hash_password(u_data["password"]),
                role=u_data["role"],
            )
            db.add(user)
    db.commit()
    db.close()
    yield
    Base.metadata.drop_all(bind=test_engine)


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def db_session():
    db = TestSessionLocal()
    try:
        yield db
    finally:
        db.close()


def _get_user(db, username: str) -> User:
    return db.query(User).filter(User.username == username).first()


def _auth_header(db, username: str = "admin") -> dict:
    user = _get_user(db, username)
    token = create_access_token(user.id, user.role.value)
    return {"Authorization": f"Bearer {token}"}


def _create_test_assessment(client, db, username="analyst"):
    headers = _auth_header(db, username)
    return client.post("/api/v1/assessments", json={
        "name": "Test Assessment",
        "description": "Test description",
        "assessment_type": "full",
        "execution_mode": "demo",
        "authorization_confirmed": True,
        "scope": {
            "targets": ["demo.lab.local"],
            "excluded_targets": [],
            "allowed_checks": [],
            "notes": "Test scope"
        }
    }, headers=headers)


# ════════════════════════════════════════════════════════════════
# Test: Health & Configuration
# ════════════════════════════════════════════════════════════════

class TestHealth:
    def test_health_endpoint(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "healthy"
        assert "version" in data
        assert "timestamp" in data

    def test_config_status_requires_auth(self, client):
        resp = client.get("/api/v1/config/status")
        assert resp.status_code == 403  # no token

    def test_config_status_with_auth(self, client, db_session):
        headers = _auth_header(db_session, "viewer")
        resp = client.get("/api/v1/config/status", headers=headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "gemini_configured" in data
        assert "demo_mode" in data
        assert data["demo_mode"] is True
        # Must not expose API key
        assert "api_key" not in json.dumps(data).lower()


# ════════════════════════════════════════════════════════════════
# Test: Authentication
# ════════════════════════════════════════════════════════════════

class TestAuth:
    def test_hash_password_produces_bcrypt_format(self):
        h = hash_password("secret_test_pass")
        assert h.startswith("$2b$") or h.startswith("$2a$")
        assert len(h) >= 50

    def test_verify_password_correct(self):
        h = hash_password("correct_password")
        assert verify_password("correct_password", h) is True

    def test_verify_password_incorrect(self):
        h = hash_password("correct_password")
        assert verify_password("incorrect_password", h) is False

    def test_verify_password_safe_on_invalid_hash(self):
        assert verify_password("test", "not_a_valid_hash") is False
        assert verify_password("test", "") is False

    def test_login_success(self, client):
        resp = client.post("/api/v1/auth/login", json={"username": "admin", "password": "admin123"})
        assert resp.status_code == 200
        data = resp.json()
        assert "access_token" in data
        assert data["user"]["username"] == "admin"
        assert data["user"]["role"] == "admin"
        assert data["username"] == "admin"
        assert data["role"] == "admin"
        assert data["user_id"] == data["user"]["id"]

    def test_login_all_seeded_users(self, client):
        for user, pwd, role in [("admin", "admin123", "admin"), ("analyst", "analyst123", "analyst"), ("viewer", "viewer123", "viewer")]:
            resp = client.post("/api/v1/auth/login", json={"username": user, "password": pwd})
            assert resp.status_code == 200, f"Failed login for {user}"
            assert resp.json()["user"]["role"] == role

    def test_login_invalid_password(self, client):
        resp = client.post("/api/v1/auth/login", json={"username": "admin", "password": "wrong"})
        assert resp.status_code == 401

    def test_login_invalid_user(self, client):
        resp = client.post("/api/v1/auth/login", json={"username": "nobody", "password": "test"})
        assert resp.status_code == 401

    def test_get_me(self, client, db_session):
        headers = _auth_header(db_session, "analyst")
        resp = client.get("/api/v1/auth/me", headers=headers)
        assert resp.status_code == 200
        assert resp.json()["username"] == "analyst"

    def test_expired_token(self, client, db_session):
        from datetime import timedelta
        user = _get_user(db_session, "admin")
        token = create_access_token(user.id, user.role.value, expires_delta=timedelta(seconds=-10))
        resp = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 401

    def test_invalid_token(self, client):
        resp = client.get("/api/v1/auth/me", headers={"Authorization": "Bearer invalid.token.here"})
        assert resp.status_code == 401


# ════════════════════════════════════════════════════════════════
# Test: RBAC
# ════════════════════════════════════════════════════════════════

class TestRBAC:
    def test_viewer_cannot_create_assessment(self, client, db_session):
        headers = _auth_header(db_session, "viewer")
        resp = client.post("/api/v1/assessments", json={
            "name": "Test", "assessment_type": "full", "execution_mode": "demo",
            "authorization_confirmed": True,
            "scope": {"targets": ["demo.lab.local"]}
        }, headers=headers)
        assert resp.status_code == 403

    def test_viewer_cannot_access_audit_logs(self, client, db_session):
        headers = _auth_header(db_session, "viewer")
        resp = client.get("/api/v1/audit-logs", headers=headers)
        assert resp.status_code == 403

    def test_analyst_cannot_access_audit_logs(self, client, db_session):
        headers = _auth_header(db_session, "analyst")
        resp = client.get("/api/v1/audit-logs", headers=headers)
        assert resp.status_code == 403

    def test_admin_can_access_audit_logs(self, client, db_session):
        headers = _auth_header(db_session, "admin")
        resp = client.get("/api/v1/audit-logs", headers=headers)
        assert resp.status_code == 200


# ════════════════════════════════════════════════════════════════
# Test: Assessments
# ════════════════════════════════════════════════════════════════

class TestAssessments:
    def test_create_assessment(self, client, db_session):
        resp = _create_test_assessment(client, db_session)
        assert resp.status_code == 201
        data = resp.json()
        assert data["name"] == "Test Assessment"
        assert data["status"] == "pending_approval"

    def test_create_assessment_with_scope_notes(self, client, db_session):
        headers = _auth_header(db_session, "analyst")
        resp = client.post("/api/v1/assessments", json={
            "name": "Staging Assessment With Notes",
            "assessment_type": "web_application",
            "execution_mode": "demo",
            "authorization_confirmed": True,
            "scope": {
                "targets": ["192.168.1.10:8080"],
                "excluded_targets": ["192.168.1.1"],
                "allowed_checks": ["reconnaissance"],
                "scope_notes": "Pre-authorized testing on staging cluster."
            }
        }, headers=headers)
        assert resp.status_code == 201
        asm_id = resp.json()["id"]

        detail_resp = client.get(f"/api/v1/assessments/{asm_id}", headers=headers)
        assert detail_resp.status_code == 200
        scope_data = detail_resp.json()["scope"]
        assert scope_data["notes"] == "Pre-authorized testing on staging cluster."
        assert scope_data["scope_notes"] == "Pre-authorized testing on staging cluster."

    def test_create_assessment_with_scope_notes_omitted(self, client, db_session):
        headers = _auth_header(db_session, "analyst")
        resp = client.post("/api/v1/assessments", json={
            "name": "Assessment Without Notes",
            "assessment_type": "web_application",
            "execution_mode": "demo",
            "authorization_confirmed": True,
            "scope": {
                "targets": ["192.168.1.10:8080"],
                "excluded_targets": [],
                "allowed_checks": []
            }
        }, headers=headers)
        assert resp.status_code == 201
        asm_id = resp.json()["id"]

        detail_resp = client.get(f"/api/v1/assessments/{asm_id}", headers=headers)
        assert detail_resp.status_code == 200
        scope_data = detail_resp.json()["scope"]
        assert scope_data["notes"] == ""
        assert scope_data["scope_notes"] == ""

    def test_create_assessment_flat_payload_with_scope_notes(self, client, db_session):
        headers = _auth_header(db_session, "analyst")
        resp = client.post("/api/v1/assessments", json={
            "name": "Flat Payload Assessment",
            "assessment_type": "web_application",
            "execution_mode": "demo",
            "targets": ["192.168.1.15:443"],
            "excluded_targets": ["192.168.1.1"],
            "allowed_checks": ["reconnaissance", "vulnerability_analysis"],
            "scope_notes": "Flat scope notes payload",
            "authorization_confirmed": True,
        }, headers=headers)
        assert resp.status_code == 201
        asm_id = resp.json()["id"]

        detail_resp = client.get(f"/api/v1/assessments/{asm_id}", headers=headers)
        assert detail_resp.status_code == 200
        scope_data = detail_resp.json()["scope"]
        assert scope_data["notes"] == "Flat scope notes payload"
        assert scope_data["scope_notes"] == "Flat scope notes payload"
        assert scope_data["targets"] == ["192.168.1.15:443"]

    def test_create_assessment_gemini_assisted_mode(self, client, db_session):
        headers = _auth_header(db_session, "analyst")
        resp = client.post("/api/v1/assessments", json={
            "name": "Staging Gemini Assessment",
            "assessment_type": "web_application",
            "execution_mode": "gemini_assisted",
            "targets": ["192.168.1.10:8080"],
            "excluded_targets": ["192.168.1.1"],
            "allowed_checks": ["reconnaissance"],
            "scope_notes": "Pre-authorized testing on staging cluster.",
            "authorization_confirmed": True,
        }, headers=headers)
        assert resp.status_code == 201
        assert resp.json()["name"] == "Staging Gemini Assessment"

    def test_create_without_authorization(self, client, db_session):
        headers = _auth_header(db_session, "analyst")
        resp = client.post("/api/v1/assessments", json={
            "name": "Test", "assessment_type": "full", "execution_mode": "demo",
            "authorization_confirmed": False,
            "scope": {"targets": ["demo.lab.local"]}
        }, headers=headers)
        assert resp.status_code == 400

    def test_list_assessments(self, client, db_session):
        _create_test_assessment(client, db_session)
        headers = _auth_header(db_session, "analyst")
        resp = client.get("/api/v1/assessments", headers=headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] >= 1
        assert data["items"][0]["scope"] is not None
        assert "demo.lab.local" in data["items"][0]["scope"]["targets"]

    def test_list_assessments_target_scope_display(self, client, db_session):
        """Verify that GET /api/v1/assessments includes target scope for table display."""
        create_resp = _create_test_assessment(client, db_session)
        a_id = create_resp.json()["id"]
        headers = _auth_header(db_session, "analyst")
        resp = client.get("/api/v1/assessments", headers=headers)
        assert resp.status_code == 200
        data = resp.json()
        matching = [item for item in data["items"] if item["id"] == a_id]
        assert len(matching) == 1
        item = matching[0]
        # Must return actual authorized targets, not empty or missing
        assert item["scope"] is not None
        assert item["scope"]["targets"] == ["demo.lab.local"]
        assert item["targets"] == ["demo.lab.local"]

    def test_get_assessment_detail(self, client, db_session):
        create_resp = _create_test_assessment(client, db_session)
        a_id = create_resp.json()["id"]
        headers = _auth_header(db_session, "analyst")
        resp = client.get(f"/api/v1/assessments/{a_id}", headers=headers)
        assert resp.status_code == 200
        assert resp.json()["id"] == a_id

    def test_approve_assessment(self, client, db_session):
        create_resp = _create_test_assessment(client, db_session)
        a_id = create_resp.json()["id"]
        headers = _auth_header(db_session, "analyst")
        resp = client.post(
            f"/api/v1/assessments/{a_id}/approve",
            json={"decision": "approved", "reason": "Pre-approved penetration test boundary confirmed."},
            headers=headers,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "approved"
        assert data["approval_status"] is True
        assert data["approved_by"] is not None
        assert data["approved_at"] is not None

        # Verify audit log recorded approver, timestamp, decision, and reason
        analyst_user = _get_user(db_session, "analyst")
        audit_entry = (
            db_session.query(AuditLog)
            .filter(
                AuditLog.resource_id == a_id,
                AuditLog.action == AuditAction.ASSESSMENT_APPROVED,
            )
            .first()
        )
        assert audit_entry is not None
        assert audit_entry.user_id == analyst_user.id
        assert audit_entry.details["decision"] == "approved"
        assert audit_entry.details["reason"] == "Pre-approved penetration test boundary confirmed."
        assert audit_entry.details["approver_username"] == "analyst"
        assert "password" not in audit_entry.details
        assert "token" not in audit_entry.details

    def test_approve_assessment_unauthorized_viewer(self, client, db_session):
        create_resp = _create_test_assessment(client, db_session, username="analyst")
        a_id = create_resp.json()["id"]
        viewer_headers = _auth_header(db_session, "viewer")
        resp = client.post(f"/api/v1/assessments/{a_id}/approve", headers=viewer_headers)
        assert resp.status_code == 403
        assert "Role 'viewer' is not authorized" in resp.json()["detail"]

    def test_approve_assessment_missing_target_scope(self, client, db_session):
        analyst_user = _get_user(db_session, "analyst")
        asm = Assessment(
            name="No Scope Assessment",
            assessment_type=AssessmentType.FULL,
            execution_mode=ExecutionMode.DEMO,
            status=AssessmentStatus.PENDING_APPROVAL,
            owner_id=analyst_user.id,
            authorization_confirmed=True,
        )
        db_session.add(asm)
        db_session.commit()
        db_session.refresh(asm)

        scope = AssessmentScope(
            assessment_id=asm.id,
            targets=[],
        )
        db_session.add(scope)
        db_session.commit()

        headers = _auth_header(db_session, "analyst")
        resp = client.post(f"/api/v1/assessments/{asm.id}/approve", headers=headers)
        assert resp.status_code == 400
        assert "scope is missing or targets list is empty" in resp.json()["detail"].lower()

    def test_approve_assessment_invalid_target_scope(self, client, db_session):
        analyst_user = _get_user(db_session, "analyst")
        asm = Assessment(
            name="Invalid Scope Assessment",
            assessment_type=AssessmentType.FULL,
            execution_mode=ExecutionMode.DEMO,
            status=AssessmentStatus.PENDING_APPROVAL,
            owner_id=analyst_user.id,
            authorization_confirmed=True,
        )
        db_session.add(asm)
        db_session.commit()
        db_session.refresh(asm)

        scope = AssessmentScope(
            assessment_id=asm.id,
            targets=["203.0.113.199"],  # not in allowed range
        )
        db_session.add(scope)
        db_session.commit()

        headers = _auth_header(db_session, "analyst")
        resp = client.post(f"/api/v1/assessments/{asm.id}/approve", headers=headers)
        assert resp.status_code == 400
        assert "scope validation failed" in resp.json()["detail"].lower()

    def test_approve_assessment_unconfirmed_authorization(self, client, db_session):
        analyst_user = _get_user(db_session, "analyst")
        asm = Assessment(
            name="Unconfirmed Auth Assessment",
            assessment_type=AssessmentType.FULL,
            execution_mode=ExecutionMode.DEMO,
            status=AssessmentStatus.PENDING_APPROVAL,
            owner_id=analyst_user.id,
            authorization_confirmed=False,
        )
        db_session.add(asm)
        db_session.commit()
        db_session.refresh(asm)

        scope = AssessmentScope(
            assessment_id=asm.id,
            targets=["demo.lab.local"],
        )
        db_session.add(scope)
        db_session.commit()

        headers = _auth_header(db_session, "analyst")
        resp = client.post(f"/api/v1/assessments/{asm.id}/approve", headers=headers)
        assert resp.status_code == 400
        assert "authorization has not been confirmed" in resp.json()["detail"].lower()

    def test_approve_assessment_repeated_approval_fails(self, client, db_session):
        create_resp = _create_test_assessment(client, db_session)
        a_id = create_resp.json()["id"]
        headers = _auth_header(db_session, "analyst")

        # First approval succeeds
        resp1 = client.post(f"/api/v1/assessments/{a_id}/approve", headers=headers)
        assert resp1.status_code == 200
        assert resp1.json()["status"] == "approved"

        # Second approval fails
        resp2 = client.post(f"/api/v1/assessments/{a_id}/approve", headers=headers)
        assert resp2.status_code == 400
        assert "cannot approve" in resp2.json()["detail"].lower()

    def test_assessment_not_found(self, client, db_session):
        headers = _auth_header(db_session, "analyst")
        resp = client.get("/api/v1/assessments/nonexistent", headers=headers)
        assert resp.status_code == 404


# ════════════════════════════════════════════════════════════════
# Test: Tenant Isolation
# ════════════════════════════════════════════════════════════════

class TestTenantIsolation:
    def test_user_cannot_see_other_users_assessment(self, client, db_session):
        # Analyst creates an assessment
        create_resp = _create_test_assessment(client, db_session, username="analyst")
        a_id = create_resp.json()["id"]

        # Viewer (non-admin) tries to access it
        headers = _auth_header(db_session, "viewer")
        resp = client.get(f"/api/v1/assessments/{a_id}", headers=headers)
        assert resp.status_code == 403

    def test_admin_can_see_all_assessments(self, client, db_session):
        _create_test_assessment(client, db_session, username="analyst")
        headers = _auth_header(db_session, "admin")
        resp = client.get("/api/v1/assessments", headers=headers)
        assert resp.status_code == 200
        assert resp.json()["total"] >= 1


# ════════════════════════════════════════════════════════════════
# Test: Scope Validation
# ════════════════════════════════════════════════════════════════

class TestScopeValidation:
    def test_valid_demo_target(self, client, db_session):
        resp = _create_test_assessment(client, db_session)
        assert resp.status_code == 201

    def test_invalid_target_blocked(self, client, db_session):
        headers = _auth_header(db_session, "analyst")
        resp = client.post("/api/v1/assessments", json={
            "name": "Bad Target Test", "assessment_type": "full",
            "execution_mode": "demo", "authorization_confirmed": True,
            "scope": {"targets": ["evil-external-site.com"]}
        }, headers=headers)
        assert resp.status_code == 400

    def test_empty_targets_rejected(self, client, db_session):
        headers = _auth_header(db_session, "analyst")
        resp = client.post("/api/v1/assessments", json={
            "name": "No Targets", "assessment_type": "full",
            "execution_mode": "demo", "authorization_confirmed": True,
            "scope": {"targets": []}
        }, headers=headers)
        assert resp.status_code == 422  # validation error


# ════════════════════════════════════════════════════════════════
# Test: Scope Validator Unit Tests
# ════════════════════════════════════════════════════════════════

class TestScopeValidatorUnit:
    def test_allowed_ip(self):
        from app.security.scope_validator import validate_target
        is_valid, _ = validate_target("192.168.1.10", ["192.168.1.0/24"])
        assert is_valid

    def test_blocked_ip(self):
        from app.security.scope_validator import validate_target
        is_valid, _ = validate_target("8.8.8.8", ["192.168.1.0/24"])
        assert not is_valid

    def test_allowed_hostname(self):
        from app.security.scope_validator import validate_target
        is_valid, _ = validate_target("app.lab.local", ["lab.local"])
        assert is_valid

    def test_blocked_hostname(self):
        from app.security.scope_validator import validate_target
        is_valid, _ = validate_target("evil.com", ["lab.local"])
        assert not is_valid

    def test_ssrf_file_scheme_blocked(self):
        from app.security.scope_validator import validate_target
        is_valid, _ = validate_target("file:///etc/passwd", ["lab.local"])
        assert not is_valid

    def test_ssrf_gopher_blocked(self):
        from app.security.scope_validator import validate_target
        is_valid, _ = validate_target("gopher://localhost", ["lab.local"])
        assert not is_valid

    def test_empty_target(self):
        from app.security.scope_validator import validate_target
        is_valid, _ = validate_target("", ["lab.local"])
        assert not is_valid

    def test_ssrf_protection(self):
        from app.security.scope_validator import check_ssrf_protection
        ok, _ = check_ssrf_protection("http://localhost/admin")
        assert not ok

    def test_ssrf_private_ip(self):
        from app.security.scope_validator import check_ssrf_protection
        ok, _ = check_ssrf_protection("http://10.0.0.1/internal")
        assert not ok


# ════════════════════════════════════════════════════════════════
# Test: Assessment Workflow
# ════════════════════════════════════════════════════════════════

class TestWorkflow:
    def test_run_requires_approval(self, client, db_session):
        create_resp = _create_test_assessment(client, db_session)
        a_id = create_resp.json()["id"]
        headers = _auth_header(db_session, "analyst")
        # Try to run without approval
        resp = client.post(f"/api/v1/assessments/{a_id}/run", headers=headers)
        assert resp.status_code == 400

    def test_run_after_approval(self, client, db_session):
        create_resp = _create_test_assessment(client, db_session)
        a_id = create_resp.json()["id"]
        headers = _auth_header(db_session, "analyst")
        # Approve
        client.post(f"/api/v1/assessments/{a_id}/approve", headers=headers)
        # Run
        resp = client.post(f"/api/v1/assessments/{a_id}/run", headers=headers)
        assert resp.status_code == 200
        assert resp.json()["status"] == "running"

    def test_stop_non_running_fails(self, client, db_session):
        create_resp = _create_test_assessment(client, db_session)
        a_id = create_resp.json()["id"]
        headers = _auth_header(db_session, "analyst")
        resp = client.post(f"/api/v1/assessments/{a_id}/stop", headers=headers)
        assert resp.status_code == 400

    @pytest.mark.asyncio
    async def test_full_workflow_execution_and_agent_status_transitions(self, client, db_session):
        from app.workflows.orchestrator import run_assessment_workflow
        from app.api.routes import _run_workflow_background
        from app.models import AgentExecution, Finding, AssessmentReport, AssessmentStatus, AgentStatus

        create_resp = _create_test_assessment(client, db_session)
        a_id = create_resp.json()["id"]
        headers = _auth_header(db_session, "analyst")

        # 1. Approval step
        appr_resp = client.post(f"/api/v1/assessments/{a_id}/approve", headers=headers)
        assert appr_resp.status_code == 200
        assert appr_resp.json()["status"] == "approved"

        # 2. Trigger workflow execution
        analyst_user = _get_user(db_session, "analyst")
        await _run_workflow_background(
            assessment_id=a_id,
            assessment_name="Test Assessment",
            assessment_type="full",
            execution_mode="demo",
            targets=["demo.lab.local"],
            excluded_targets=[],
            allowed_checks=[],
            scope_notes="Authorized demo test",
            user_id=analyst_user.id,
        )

        # 3. Verify assessment status in DB
        asm = db_session.query(Assessment).filter(Assessment.id == a_id).first()
        assert asm.status == AssessmentStatus.COMPLETED
        assert asm.completed_at is not None

        # 4. Verify all 6 agents transitioned to COMPLETED with evidence/summaries
        aes = (
            db_session.query(AgentExecution)
            .filter(AgentExecution.assessment_id == a_id)
            .order_by(AgentExecution.step_order)
            .all()
        )
        assert len(aes) == 6
        for ae in aes:
            assert ae.status == AgentStatus.COMPLETED
            assert ae.started_at is not None
            assert ae.completed_at is not None
            assert ae.output_summary is not None

        # 5. Verify findings recorded with evidence and severity
        findings = db_session.query(Finding).filter(Finding.assessment_id == a_id).all()
        assert len(findings) > 0
        for f in findings:
            assert f.title is not None
            assert f.evidence is not None
            assert f.severity is not None

        # 6. Verify report generated with executive summary
        report = db_session.query(AssessmentReport).filter(AssessmentReport.assessment_id == a_id).first()
        assert report is not None
        assert report.executive_summary is not None
        assert report.report_json is not None
        assert report.report_html is not None

        # 7. Verify GET /api/v1/assessments/{id} returns agent executions, findings count, and report
        detail_resp = client.get(f"/api/v1/assessments/{a_id}", headers=headers)
        assert detail_resp.status_code == 200
        detail = detail_resp.json()
        assert detail["status"] == "completed"
        assert len(detail["agent_executions"]) == 6
        assert detail["findings_count"] == len(findings)

    @pytest.mark.asyncio
    async def test_workflow_failure_handling(self, client, db_session):
        from app.api.routes import _run_workflow_background
        from app.models import AssessmentStatus, AgentStatus, AgentExecution

        create_resp = _create_test_assessment(client, db_session)
        a_id = create_resp.json()["id"]
        headers = _auth_header(db_session, "analyst")

        client.post(f"/api/v1/assessments/{a_id}/approve", headers=headers)
        analyst_user = _get_user(db_session, "analyst")

        # Run with invalid assessment type to trigger planning failure
        await _run_workflow_background(
            assessment_id=a_id,
            assessment_name="Failing Assessment",
            assessment_type="invalid_type_xyz",
            execution_mode="demo",
            targets=["demo.lab.local"],
            excluded_targets=[],
            allowed_checks=[],
            scope_notes=None,
            user_id=analyst_user.id,
        )

        asm = db_session.query(Assessment).filter(Assessment.id == a_id).first()
        assert asm.status == AssessmentStatus.FAILED
        assert asm.error_message is not None

    @pytest.mark.asyncio
    async def test_workflow_enforces_target_scope_exclusion(self, client, db_session):
        from app.workflows.orchestrator import run_assessment_workflow

        create_resp = _create_test_assessment(client, db_session)
        a_id = create_resp.json()["id"]

        # Targets with one excluded target
        result = await run_assessment_workflow(
            assessment_id=a_id,
            assessment_name="Scope Test",
            assessment_type="full",
            execution_mode="demo",
            targets=["demo.lab.local", "192.168.1.99"],
            excluded_targets=["192.168.1.99"],
            allowed_checks=[],
            scope_notes="Exclusion test",
            db_session=db_session,
        )
        assert result["workflow_status"] == "completed"
        # Excluded target must not be in final state targets
        assert "192.168.1.99" not in result["targets"]
        assert "demo.lab.local" in result["targets"]


# ════════════════════════════════════════════════════════════════
# Test: Agent Workflow Unit Tests
# ════════════════════════════════════════════════════════════════

class TestAgentWorkflow:
    @pytest.mark.asyncio
    async def test_planning_agent_valid(self):
        from app.agents.planning_agent import planning_agent
        state = {
            "assessment_id": "test-123",
            "assessment_type": "full",
            "targets": ["demo.lab.local"],
            "execution_mode": "demo",
            "allowed_checks": [],
        }
        result = await planning_agent(state)
        assert "plan_steps" in result
        assert len(result["plan_steps"]) > 0
        assert result.get("workflow_status") != "failed"

    @pytest.mark.asyncio
    async def test_planning_agent_invalid_type(self):
        from app.agents.planning_agent import planning_agent
        state = {
            "assessment_id": "test-123",
            "assessment_type": "nonexistent_type",
            "targets": ["demo.lab.local"],
            "execution_mode": "demo",
        }
        result = await planning_agent(state)
        assert result["workflow_status"] == "failed"

    @pytest.mark.asyncio
    async def test_planning_agent_no_targets(self):
        from app.agents.planning_agent import planning_agent
        state = {
            "assessment_id": "test-123",
            "assessment_type": "full",
            "targets": [],
            "execution_mode": "demo",
        }
        result = await planning_agent(state)
        assert result["workflow_status"] == "failed"

    @pytest.mark.asyncio
    async def test_recon_agent(self):
        from app.agents.recon_agent import recon_agent
        state = {
            "assessment_id": "test-123",
            "targets": ["demo.lab.local"],
            "execution_mode": "demo",
        }
        result = await recon_agent(state)
        assert "recon_observations" in result
        assert len(result["recon_observations"]) > 0

    @pytest.mark.asyncio
    async def test_vulnerability_agent(self):
        from app.agents.vulnerability_agent import vulnerability_agent
        state = {
            "assessment_id": "test-123",
            "execution_mode": "demo",
            "recon_observations": [],
        }
        result = await vulnerability_agent(state)
        assert "raw_findings" in result
        assert len(result["raw_findings"]) > 0

    @pytest.mark.asyncio
    async def test_validation_agent_dedup(self):
        from app.agents.validation_agent import validation_agent
        state = {
            "assessment_id": "test-123",
            "execution_mode": "demo",
            "raw_findings": [
                {"title": "Finding A", "affected_asset": "test", "evidence": "synthetic test", "source_type": "synthetic"},
                {"title": "Finding A", "affected_asset": "test", "evidence": "synthetic test", "source_type": "synthetic"},
                {"title": "Finding B", "affected_asset": "test", "evidence": "", "source_type": "synthetic"},
            ],
            "recon_observations": [],
        }
        result = await validation_agent(state)
        assert result["duplicates_found"] == 1
        assert len(result["validated_findings"]) == 2

    @pytest.mark.asyncio
    async def test_validation_agent_empty(self):
        from app.agents.validation_agent import validation_agent
        state = {"assessment_id": "test-123", "execution_mode": "demo", "raw_findings": [], "recon_observations": []}
        result = await validation_agent(state)
        assert len(result["validated_findings"]) == 0

    @pytest.mark.asyncio
    async def test_risk_agent(self):
        from app.agents.risk_agent import risk_agent
        state = {
            "assessment_id": "test-123",
            "execution_mode": "demo",
            "validated_findings": [
                {"title": "SQL Injection", "description": "SQL injection in login form", "severity": "high", "confidence": "suspected"},
                {"title": "Missing Header", "description": "Missing security header", "severity": "low", "confidence": "suspected"},
            ],
        }
        result = await risk_agent(state)
        assert result["overall_risk"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL")
        assert len(result["risk_assessed_findings"]) == 2

    @pytest.mark.asyncio
    async def test_report_agent(self):
        from app.agents.report_agent import report_agent
        state = {
            "assessment_id": "test-123",
            "assessment_name": "Test Assessment",
            "execution_mode": "demo",
            "targets": ["demo.lab.local"],
            "risk_assessed_findings": [
                {
                    "title": "Test Finding",
                    "description": "Test description",
                    "affected_asset": "demo.lab.local",
                    "severity": "medium",
                    "confidence": "suspected",
                    "validation_status": "suspected",
                    "evidence": "Synthetic evidence",
                    "cwe_id": "CWE-326",
                    "remediation": "Fix it",
                    "references": [],
                    "source_type": "synthetic",
                }
            ],
            "plan_limitations": ["Demo mode"],
            "missing_evidence": [],
            "overall_risk": "MEDIUM",
            "remediation_priorities": ["Fix it"],
        }
        result = await report_agent(state)
        assert result["report_json"] is not None
        assert result["report_html"] is not None
        assert "DEMO" in result["executive_summary"]
        assert result["workflow_status"] == "completed"


# ════════════════════════════════════════════════════════════════
# Test: Report Schema Validation
# ════════════════════════════════════════════════════════════════

class TestReportSchema:
    def test_report_schema_valid(self):
        from app.schemas import ReportSchema, ReportFinding, SeveritySummary
        report = ReportSchema(
            assessment_id="test-123",
            assessment_name="Test",
            assessment_mode="demo",
            scope=["demo.lab.local"],
            authorization_status="confirmed",
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
            overall_status="completed",
            executive_summary="Test summary",
            methodology="Test methodology",
            findings=[
                ReportFinding(
                    finding_id="FIND-001",
                    title="Test",
                    description="Test desc",
                    severity="medium",
                    confidence="suspected",
                    validation_status="suspected",
                    source_type="synthetic",
                )
            ],
            severity_summary=SeveritySummary(medium=1),
            limitations="Demo mode",
            remediation_priorities=["Fix it"],
            generated_at=datetime.now(timezone.utc),
        )
        assert report.assessment_id == "test-123"


# ════════════════════════════════════════════════════════════════
# Test: HTML Escaping
# ════════════════════════════════════════════════════════════════

class TestHTMLEscaping:
    @pytest.mark.asyncio
    async def test_html_report_escapes_xss(self):
        from app.agents.report_agent import report_agent
        state = {
            "assessment_id": "test-xss",
            "assessment_name": '<script>alert("xss")</script>',
            "execution_mode": "demo",
            "targets": ["demo.lab.local"],
            "risk_assessed_findings": [
                {
                    "title": '<img src=x onerror=alert(1)>',
                    "description": "Normal description",
                    "affected_asset": "demo.lab.local",
                    "severity": "low",
                    "confidence": "suspected",
                    "validation_status": "suspected",
                    "evidence": "Test",
                    "cwe_id": None,
                    "remediation": "Fix",
                    "references": [],
                    "source_type": "synthetic",
                }
            ],
            "plan_limitations": [],
            "missing_evidence": [],
            "overall_risk": "LOW",
            "remediation_priorities": [],
        }
        result = await report_agent(state)
        html_content = result["report_html"]
        # XSS payloads must be escaped
        assert '<script>alert("xss")</script>' not in html_content
        assert '<img src=x onerror=alert(1)>' not in html_content
        assert '&lt;script&gt;' in html_content


# ════════════════════════════════════════════════════════════════
# Test: Audit Logging
# ════════════════════════════════════════════════════════════════

class TestAuditLogging:
    def test_login_creates_audit_log(self, client, db_session):
        client.post("/api/v1/auth/login", json={"username": "admin", "password": "admin123"})
        from app.models import AuditLog, AuditAction
        logs = db_session.query(AuditLog).filter(AuditLog.action == AuditAction.LOGIN).all()
        assert len(logs) >= 1

    def test_failed_login_creates_audit_log(self, client, db_session):
        client.post("/api/v1/auth/login", json={"username": "admin", "password": "wrong"})
        from app.models import AuditLog, AuditAction
        logs = db_session.query(AuditLog).filter(AuditLog.action == AuditAction.AUTH_FAILURE).all()
        assert len(logs) >= 1

    def test_audit_redacts_secrets(self, db_session):
        from app.services.audit_service import log_audit_event
        entry = log_audit_event(
            db_session,
            AuditAction.LOGIN,
            details={"password": "secret123", "api_key": "real-key", "username": "admin"},
        )
        assert entry.details["password"] == "***REDACTED***"
        assert entry.details["api_key"] == "***REDACTED***"
        assert entry.details["username"] == "admin"


# ════════════════════════════════════════════════════════════════
# Test: Demo Mode
# ════════════════════════════════════════════════════════════════

class TestDemoMode:
    def test_demo_mode_active(self, client, db_session):
        headers = _auth_header(db_session, "viewer")
        resp = client.get("/api/v1/config/status", headers=headers)
        assert resp.json()["demo_mode"] is True

    @pytest.mark.asyncio
    async def test_demo_findings_labeled_synthetic(self):
        from app.agents.vulnerability_agent import vulnerability_agent
        state = {
            "assessment_id": "demo-test",
            "execution_mode": "demo",
            "recon_observations": [],
        }
        result = await vulnerability_agent(state)
        for finding in result["raw_findings"]:
            assert finding["source_type"] == "synthetic"


# ════════════════════════════════════════════════════════════════
# Test: Gemini Error Handling
# ════════════════════════════════════════════════════════════════

class TestGeminiErrorHandling:
    def test_provider_not_available_in_demo(self):
        from app.services.gemini_provider import get_llm_provider, DemoProvider
        provider = get_llm_provider()
        assert isinstance(provider, DemoProvider)

    @pytest.mark.asyncio
    async def test_demo_provider_returns_data(self):
        from app.services.gemini_provider import DemoProvider
        provider = DemoProvider()
        result = await provider.generate("Test plan creation")
        assert result is not None
        assert len(result) > 0

    def test_gemini_provider_handles_missing_key(self, monkeypatch):
        from app.services.gemini_provider import GeminiProvider
        from app.core.config import Settings
        empty_settings = Settings(gemini_api_key=None, demo_mode=True)
        monkeypatch.setattr("app.services.gemini_provider.get_settings", lambda: empty_settings)
        provider = GeminiProvider()
        assert not provider.is_available


# ════════════════════════════════════════════════════════════════
# Test: SQLAlchemy Model Relationships Regression Tests
# ════════════════════════════════════════════════════════════════

class TestSQLAlchemyModelRelationships:
    def test_seed_default_users_without_ambiguous_foreign_keys_error(self, db_session):
        """
        Regression test for AmbiguousForeignKeysError:
        Verifies that querying User and seeding users compiles the mapper successfully
        without AmbiguousForeignKeysError on User.assessments vs Assessment.owner_id / approved_by.
        """
        from app.main import _seed_default_users
        _seed_default_users(db_session)
        users = db_session.query(User).all()
        assert len(users) >= 3

    def test_user_and_assessment_relationships_and_foreign_keys(self, db_session):
        """
        Verifies that:
        1. User.assessments joins on Assessment.owner_id
        2. User.approved_assessments joins on Assessment.approved_by
        3. Assessment.owner references the owner User
        4. Assessment.approver references the approver User
        """
        from app.models import Assessment, AssessmentType, ExecutionMode, AssessmentStatus

        owner = db_session.query(User).filter(User.username == "analyst").first()
        approver = db_session.query(User).filter(User.username == "admin").first()
        assert owner is not None
        assert approver is not None

        # Create assessment with distinct owner and approver
        asm = Assessment(
            name="Relationship Verification Assessment",
            assessment_type=AssessmentType.FULL,
            execution_mode=ExecutionMode.DEMO,
            status=AssessmentStatus.APPROVED,
            owner_id=owner.id,
            approved_by=approver.id,
            authorization_confirmed=True,
        )
        db_session.add(asm)
        db_session.commit()
        db_session.refresh(asm)

        # Verify forward relationships
        assert asm.owner.id == owner.id
        assert asm.owner.username == "analyst"
        assert asm.approver.id == approver.id
        assert asm.approver.username == "admin"

        # Verify reverse relationships
        owner_assessments = owner.assessments.all()
        assert any(a.id == asm.id for a in owner_assessments)

        approver_approved = approver.approved_assessments.all()
        assert any(a.id == asm.id for a in approver_approved)

        # Verify approver is not marked as owner
        approver_owned = approver.assessments.all()
        assert not any(a.id == asm.id for a in approver_owned)


# ════════════════════════════════════════════════════════════════
# Test: Report Access & Authentication
# ════════════════════════════════════════════════════════════════

class TestReportAccess:
    def _seed_completed_assessment_with_report(self, db, owner_username="analyst"):
        from app.models import (
            Assessment, AssessmentScope, AssessmentReport, Finding,
            AssessmentStatus, AssessmentType, ExecutionMode, Severity, Confidence
        )
        owner = _get_user(db, owner_username)
        admin = _get_user(db, "admin")

        asm = Assessment(
            name="Staging Security Assessment",
            description="Testing report endpoint",
            assessment_type=AssessmentType.FULL,
            execution_mode=ExecutionMode.DEMO,
            status=AssessmentStatus.COMPLETED,
            owner_id=owner.id,
            approved_by=admin.id,
            authorization_confirmed=True,
        )
        db.add(asm)
        db.flush()

        scope = AssessmentScope(
            assessment_id=asm.id,
            targets=["staging.example.com"],
            notes="Testing scope",
        )
        db.add(scope)

        finding = Finding(
            assessment_id=asm.id,
            title="Outdated TLS Configuration",
            description="Server supports TLS 1.0 which is deprecated.",
            affected_asset="staging.example.com:443",
            severity=Severity.HIGH,
            confidence=Confidence.CONFIRMED,
            evidence="TLS 1.0 handshake accepted",
            remediation="Disable TLS 1.0 and TLS 1.1; enforce TLS 1.2+.",
        )
        db.add(finding)

        report = AssessmentReport(
            assessment_id=asm.id,
            report_json={
                "assessment_id": asm.id,
                "assessment_name": asm.name,
                "findings": [{
                    "title": "Outdated TLS Configuration",
                    "severity": "high",
                    "affected_asset": "staging.example.com:443"
                }],
                "overall_risk": "HIGH",
            },
            report_html=(
                "<!DOCTYPE html><html><body>"
                "<h1>SentinelAI Security Report: Staging Security Assessment</h1>"
                "<div class='finding'><h3>Outdated TLS Configuration</h3>"
                "<p>Severity: HIGH</p><p>Asset: staging.example.com:443</p></div>"
                "</body></html>"
            ),
            executive_summary="Security assessment identified 1 high severity finding.",
        )
        db.add(report)
        db.commit()
        db.refresh(asm)
        return asm

    def test_get_report_html_unauthenticated_rejected(self, client, db_session):
        asm = self._seed_completed_assessment_with_report(db_session)
        # Direct unauthenticated request (without Authorization header) rejects with "Not authenticated"
        resp = client.get(f"/api/v1/assessments/{asm.id}/report/html")
        assert resp.status_code in (401, 403)
        assert resp.json()["detail"] == "Not authenticated"

    def test_get_report_html_invalid_token_returns_401(self, client, db_session):
        asm = self._seed_completed_assessment_with_report(db_session)
        resp = client.get(
            f"/api/v1/assessments/{asm.id}/report/html",
            headers={"Authorization": "Bearer invalid.token.value"}
        )
        assert resp.status_code == 401
        assert resp.json()["detail"] == "Invalid token"

    def test_get_report_json_unauthenticated_rejected(self, client, db_session):
        asm = self._seed_completed_assessment_with_report(db_session)
        resp = client.get(f"/api/v1/assessments/{asm.id}/report")
        assert resp.status_code in (401, 403)
        assert resp.json()["detail"] == "Not authenticated"

    def test_get_report_html_authenticated_owner_returns_200(self, client, db_session):
        asm = self._seed_completed_assessment_with_report(db_session, owner_username="analyst")
        headers = _auth_header(db_session, "analyst")
        resp = client.get(f"/api/v1/assessments/{asm.id}/report/html", headers=headers)
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]
        # Verify actual persisted findings and assessment metadata in HTML
        assert "Staging Security Assessment" in resp.text
        assert "Outdated TLS Configuration" in resp.text
        assert "staging.example.com:443" in resp.text

    def test_get_report_html_authenticated_admin_returns_200(self, client, db_session):
        asm = self._seed_completed_assessment_with_report(db_session, owner_username="analyst")
        headers = _auth_header(db_session, "admin")
        resp = client.get(f"/api/v1/assessments/{asm.id}/report/html", headers=headers)
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]
        assert "Staging Security Assessment" in resp.text

    def test_get_report_html_unauthorized_user_returns_403(self, client, db_session):
        # Create assessment owned by analyst
        asm = self._seed_completed_assessment_with_report(db_session, owner_username="analyst")
        # Viewer user tries to access analyst's assessment
        headers = _auth_header(db_session, "viewer")
        resp = client.get(f"/api/v1/assessments/{asm.id}/report/html", headers=headers)
        assert resp.status_code == 403
        assert resp.json()["detail"] == "Access denied"

    def test_get_report_html_not_found(self, client, db_session):
        headers = _auth_header(db_session, "admin")
        resp = client.get("/api/v1/assessments/nonexistent_id/report/html", headers=headers)
        assert resp.status_code == 404
        assert resp.json()["detail"] == "Assessment not found"

    def test_get_report_html_not_generated_returns_404(self, client, db_session):
        from app.models import Assessment, AssessmentStatus, AssessmentType, ExecutionMode
        owner = _get_user(db_session, "analyst")
        asm = Assessment(
            name="No Report Assessment",
            assessment_type=AssessmentType.FULL,
            execution_mode=ExecutionMode.DEMO,
            status=AssessmentStatus.RUNNING,
            owner_id=owner.id,
            authorization_confirmed=True,
        )
        db_session.add(asm)
        db_session.commit()

        headers = _auth_header(db_session, "analyst")
        resp = client.get(f"/api/v1/assessments/{asm.id}/report/html", headers=headers)
        assert resp.status_code == 404
        assert resp.json()["detail"] == "HTML report not yet generated"

    def test_report_accessed_audit_log_created(self, client, db_session):
        from app.models import AuditLog, AuditAction
        asm = self._seed_completed_assessment_with_report(db_session, owner_username="analyst")
        headers = _auth_header(db_session, "analyst")

        initial_count = db_session.query(AuditLog).filter(
            AuditLog.action == AuditAction.REPORT_ACCESSED,
            AuditLog.resource_id == asm.id
        ).count()

        resp = client.get(f"/api/v1/assessments/{asm.id}/report/html", headers=headers)
        assert resp.status_code == 200

        new_count = db_session.query(AuditLog).filter(
            AuditLog.action == AuditAction.REPORT_ACCESSED,
            AuditLog.resource_id == asm.id
        ).count()
        assert new_count == initial_count + 1


# ════════════════════════════════════════════════════════════════
# Test: Report Polishing, Target Mapping, Risk & Provenance
# ════════════════════════════════════════════════════════════════

class TestReportPolishing:
    def test_target_mapping_helper_exact_and_subdomain(self):
        from app.agents.report_agent import check_asset_target_mapping

        targets = ["192.168.1.10:8080", "staging.corp.internal"]

        # Exact match with port
        is_mapped, matched = check_asset_target_mapping("192.168.1.10:8080", targets)
        assert is_mapped is True
        assert matched == "192.168.1.10:8080"

        # Host-only match to target with port
        is_mapped, matched = check_asset_target_mapping("192.168.1.10", targets)
        assert is_mapped is True
        assert matched == "192.168.1.10:8080"

        # Subdomain match on domain target
        is_mapped, matched = check_asset_target_mapping("api.staging.corp.internal", targets)
        assert is_mapped is True
        assert matched == "staging.corp.internal"

        # Unmapped assets (outside scope)
        is_mapped, matched = check_asset_target_mapping("demo.lab.local", targets)
        assert is_mapped is False
        assert matched is None

        # None or empty
        assert check_asset_target_mapping(None, targets) == (False, None)
        assert check_asset_target_mapping("", targets) == (False, None)
        assert check_asset_target_mapping("unknown", targets) == (False, None)

    def test_report_separates_execution_status_from_overall_risk(self):
        from app.agents.report_agent import _generate_html_report

        report_data = {
            "assessment_name": "Risk Separation Test",
            "assessment_id": "asm-risk-sep-001",
            "assessment_mode": "demo",
            "scope": ["10.0.0.1"],
            "overall_status": "completed",
            "findings": [
                {
                    "finding_id": "FIND-001",
                    "title": "Critical RCE",
                    "severity": "critical",
                    "confidence": "suspected",
                    "source_type": "synthetic",
                    "affected_asset": "10.0.0.1",
                    "remediation": "Apply critical security update.",
                }
            ],
            "severity_summary": {"critical": 1, "high": 0, "medium": 0, "low": 0, "informational": 0},
        }

        html = _generate_html_report(report_data)

        # Must NOT conflate overall risk with execution status
        assert "Overall Risk: COMPLETED" not in html
        # Must clearly show both
        assert "Execution Status" in html
        assert "COMPLETED" in html
        assert "Overall Risk Rating" in html
        assert "CRITICAL" in html

    def test_synthetic_findings_clearly_labeled_and_not_presented_as_verified(self):
        from app.agents.report_agent import _generate_html_report

        report_data = {
            "assessment_name": "Synthetic Labeling Test",
            "assessment_id": "asm-synth-001",
            "assessment_mode": "llm_assisted",
            "scope": ["10.0.0.1"],
            "overall_status": "completed",
            "findings": [
                {
                    "finding_id": "FIND-001",
                    "title": "Simulated TLS Issue",
                    "severity": "high",
                    "confidence": "suspected",
                    "validation_status": "confirmed",
                    "source_type": "synthetic",
                    "affected_asset": "10.0.0.1",
                    "remediation": "Upgrade TLS configuration.",
                }
            ],
        }

        html = _generate_html_report(report_data)

        # Synthetic banner
        assert "SYNTHETIC EVIDENCE NOTICE" in html
        # Synthetic badge on finding
        assert "SYNTHETIC EVIDENCE (DEMO)" in html
        # Not live verified badge
        assert "NOT LIVE VERIFIED" in html
        # Limitations note
        assert "Synthetic evidence generated for simulation" in html

    def test_gemini_usage_detected_and_displayed(self):
        from app.agents.report_agent import _generate_html_report

        # 1. Gemini actively used
        report_data_active = {
            "assessment_name": "Gemini Active Test",
            "assessment_id": "asm-gemini-active",
            "assessment_mode": "llm_assisted",
            "gemini_used": True,
            "gemini_model": "gemini-3.8-flash",
            "scope": ["10.0.0.1"],
            "findings": [],
        }
        html_active = _generate_html_report(report_data_active)
        assert "GEMINI ACTIVE (gemini-3.8-flash)" in html_active

        # 2. Gemini not used (demo mode)
        report_data_demo = {
            "assessment_name": "Gemini Demo Test",
            "assessment_id": "asm-gemini-demo",
            "assessment_mode": "demo",
            "scope": ["10.0.0.1"],
            "findings": [],
        }
        html_demo = _generate_html_report(report_data_demo)
        assert "GEMINI NOT USED" in html_demo

    def test_unmapped_affected_assets_flagged(self):
        from app.agents.report_agent import _generate_html_report

        report_data = {
            "assessment_name": "Unmapped Target Test",
            "assessment_id": "asm-unmapped-001",
            "assessment_mode": "demo",
            "scope": ["192.168.1.10:8080", "192.168.1.15:443"],
            "findings": [
                {
                    "finding_id": "FIND-001",
                    "title": "Unmapped Host Vulnerability",
                    "severity": "high",
                    "affected_asset": "demo.lab.local",
                    "source_type": "synthetic",
                    "confidence": "suspected",
                    "remediation": "Fix the issue.",
                },
                {
                    "finding_id": "FIND-002",
                    "title": "In Scope Vulnerability",
                    "severity": "medium",
                    "affected_asset": "192.168.1.10:8080",
                    "source_type": "synthetic",
                    "confidence": "suspected",
                    "remediation": "Fix in scope issue.",
                }
            ],
        }

        html = _generate_html_report(report_data)

        # Verify unmapped alert badge & scope warning
        assert "UNMAPPED ASSET" in html
        assert "Target Scope Alert" in html
        assert "Outside Authorized Scope Targets" in html
        # Verify mapped badge is also present for the in-scope asset
        assert "IN SCOPE (192.168.1.10:8080)" in html

    def test_remediation_renders_completely_without_truncation(self):
        from app.agents.report_agent import _generate_html_report

        long_remediation = (
            "Update synthetic-lib to version 1.2.5 or later. If immediate update is not possible, "
            "implement Web Application Firewall rules to block known exploit patterns. Review "
            "application code that uses the vulnerable library for additional hardening. Verify "
            "integrity of all deployment artifacts."
        )
        assert len(long_remediation) > 250

        report_data = {
            "assessment_name": "Remediation Truncation Test",
            "assessment_id": "asm-rem-001",
            "assessment_mode": "demo",
            "scope": ["10.0.0.1"],
            "findings": [
                {
                    "finding_id": "FIND-001",
                    "title": "RCE in Library",
                    "severity": "critical",
                    "affected_asset": "10.0.0.1",
                    "remediation": long_remediation,
                    "source_type": "synthetic",
                }
            ],
            "remediation_priorities": [
                f"Priority 1 [CRITICAL]: RCE in Library — {long_remediation[:200]}"
            ],
        }

        html = _generate_html_report(report_data)

        # Must contain full text in both finding card and priorities
        assert long_remediation in html
        assert "Verify integrity of all deployment artifacts." in html

    def test_finding_metadata_includes_provenance_confidence_verification_limitations(self):
        from app.agents.report_agent import _generate_html_report

        report_data = {
            "assessment_name": "Finding Metadata Test",
            "assessment_id": "asm-meta-001",
            "assessment_mode": "demo",
            "scope": ["10.0.0.1"],
            "findings": [
                {
                    "finding_id": "FIND-001",
                    "title": "Detailed Finding",
                    "severity": "medium",
                    "confidence": "suspected",
                    "validation_status": "suspected",
                    "source_type": "synthetic",
                    "evidence": "Observed weak cipher suite TLS_RSA_WITH_3DES_EDE_CBC_SHA in scan evidence",
                    "affected_asset": "10.0.0.1",
                    "cwe_id": "CWE-326",
                    "remediation": "Disable 3DES cipher suites.",
                }
            ],
        }

        html = _generate_html_report(report_data)

        assert "Evidence Provenance:" in html
        assert "Confidence Level:" in html
        assert "Verification Status:" in html
        assert "Finding Limitations:" in html
        assert "CWE Identifier:" in html
        assert "CWE-326" in html
        assert "Observed weak cipher suite TLS_RSA_WITH_3DES_EDE_CBC_SHA" in html


class TestEndToEndWorkflowAndScopeEnforcement:
    """Verifies scope enforcement, Gemini usage truthfulness, and finding verification."""

    def test_gemini_fallback_labeling_accuracy(self):
        from app.agents.report_agent import _detect_gemini_usage

        # Never claim Gemini was used if gemini_used is False
        fallback_data = {
            "assessment_mode": "llm_assisted",
            "gemini_used": False,
        }
        used, badge, desc = _detect_gemini_usage(fallback_data)
        assert used is False
        assert "GEMINI NOT USED" in badge
        assert "Deterministic fallback engine" in desc

        # Accurate claim only when gemini_used is True
        active_data = {
            "assessment_mode": "llm_assisted",
            "gemini_used": True,
            "gemini_model": "gemini-3-flash-preview",
        }
        used, badge, desc = _detect_gemini_usage(active_data)
        assert used is True
        assert "GEMINI ACTIVE (gemini-3-flash-preview)" in badge
        assert "gemini-3-flash-preview" in desc

    @pytest.mark.asyncio
    async def test_validation_agent_enforces_scope_and_exclusions(self):
        from app.agents.validation_agent import validation_agent

        state = {
            "assessment_id": "test-scope-asm",
            "execution_mode": "llm_assisted",
            "targets": ["192.168.1.10", "app.lab.local"],
            "excluded_targets": ["192.168.1.99", "prod.corp.com"],
            "raw_findings": [
                {
                    "title": "Finding on In-Scope Host",
                    "affected_asset": "app.lab.local:8080",
                    "evidence": "verified vulnerability on authorized asset",
                    "source_type": "static_analysis",
                    "severity": "high",
                },
                {
                    "title": "Finding on Excluded Target",
                    "affected_asset": "192.168.1.99",
                    "evidence": "verified vulnerability",
                    "source_type": "static_analysis",
                    "severity": "critical",
                },
                {
                    "title": "Finding on Unmapped Outside Asset",
                    "affected_asset": "attacker-c2.evil.com",
                    "evidence": "verified",
                    "source_type": "static_analysis",
                    "severity": "critical",
                },
                {
                    "title": "LLM Generated Finding (Must Never Be Confirmed Without Live Evidence)",
                    "affected_asset": "192.168.1.10",
                    "evidence": "confirmed by AI model reasoning",
                    "source_type": "llm_generated",
                    "severity": "medium",
                },
            ],
        }

        result = await validation_agent(state)
        validated = result["validated_findings"]
        assert len(validated) == 4

        # 1. In-scope host
        f_in_scope = next(f for f in validated if f["affected_asset"] == "app.lab.local:8080")
        assert f_in_scope["scope_validation"] == "AUTHORIZED"
        assert f_in_scope["affected_port"] == "8080"
        assert f_in_scope["confidence"] == "confirmed"

        # 2. Excluded target
        f_excluded = next(f for f in validated if f["affected_asset"] == "192.168.1.99")
        assert f_excluded["scope_validation"] == "OUT_OF_SCOPE"
        assert f_excluded["confidence"] == "unverified"
        assert f_excluded["validation_status"] == "unverified"

        # 3. Unmapped outside asset
        f_unmapped = next(f for f in validated if f["affected_asset"] == "attacker-c2.evil.com")
        assert f_unmapped["scope_validation"] == "OUT_OF_SCOPE"
        assert f_unmapped["confidence"] == "unverified"

        # 4. LLM generated cannot be confirmed
        f_llm = next(f for f in validated if f["title"].startswith("LLM Generated"))
        assert f_llm["scope_validation"] == "AUTHORIZED"
        assert f_llm["confidence"] == "suspected"
        assert f_llm["validation_status"] == "suspected"

    def test_finding_and_report_schema_port_and_risk_rating(self):
        from app.schemas import FindingOut, ReportFinding
        from datetime import datetime, timezone

        finding_dict = {
            "id": "find-1",
            "assessment_id": "asm-1",
            "title": "Open Port",
            "description": "Database exposed",
            "affected_asset": "db.internal.net:5432",
            "severity": "high",
            "confidence": "suspected",
            "validation_status": "suspected",
            "evidence": "port open",
            "created_at": datetime.now(timezone.utc),
        }

        finding_out = FindingOut.model_validate(finding_dict)
        assert finding_out.affected_port == "5432"
        assert finding_out.risk_rating == "HIGH"
        assert finding_out.originating_agent == "Vulnerability Analysis Agent"

        rep_dict = {
            "finding_id": "FIND-001",
            "title": "Open Port",
            "description": "Database exposed",
            "affected_asset": "10.0.0.5:8443",
            "severity": "critical",
            "confidence": "confirmed",
            "validation_status": "confirmed",
        }
        rep_finding = ReportFinding.model_validate(rep_dict)
        assert rep_finding.affected_port == "8443"
        assert rep_finding.risk_rating == "CRITICAL"
        assert rep_finding.scope_validation == "AUTHORIZED"

    def test_recursive_audit_secret_redaction(self, db_session):
        from app.services.audit_service import log_audit_event
        from app.models import AuditAction

        details = {
            "normal_field": "safe_value",
            "nested": {
                "user_token": "secret_bearer_token",
                "api_key": "secret_gemini_key",
                "deep": [
                    {"password": "secret_plaintext_pw"},
                    {"safe": "ok"},
                ],
            },
        }

        log = log_audit_event(
            db_session,
            AuditAction.LOGIN,
            user_id=None,
            details=details,
        )

        assert log.details["normal_field"] == "safe_value"
        assert log.details["nested"]["user_token"] == "***REDACTED***"
        assert log.details["nested"]["api_key"] == "***REDACTED***"
        assert log.details["nested"]["deep"][0]["password"] == "***REDACTED***"
        assert log.details["nested"]["deep"][1]["safe"] == "ok"



