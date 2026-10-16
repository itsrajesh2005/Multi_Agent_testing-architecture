# SentinelAI — REST API Reference

Base URL: `http://localhost:8000`  
Interactive OpenAPI Documentation: `http://localhost:8000/docs`  
ReDoc Documentation: `http://localhost:8000/redoc`

All authenticated endpoints require an `Authorization: Bearer <token>` HTTP header.

---

## 1. System & Health

### `GET /health`
Returns the operational health and version status of the application.
- **Auth:** None (Public)
- **Response `200 OK`:**
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "timestamp": "2026-10-16T09:15:00Z"
}
```

### `GET /api/v1/config/status`
Returns safe configuration status without exposing sensitive environment variables.
- **Auth:** Viewer, Analyst, or Admin
- **Response `200 OK`:**
```json
{
  "app_env": "development",
  "demo_mode": true,
  "gemini_configured": false,
  "gemini_model": "gemini-2.0-flash",
  "database_type": "sqlite",
  "allowed_lab_targets": ["192.168.1.0/24", "10.0.0.0/8", "lab.local"],
  "require_human_approval": true,
  "rate_limit_per_minute": 60
}
```

---

## 2. Authentication

### `POST /api/v1/auth/login`
Authenticates a user and returns a signed JWT access token.
- **Request Body:**
```json
{
  "username": "admin",
  "password": "admin123"
}
```
- **Response `200 OK`:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsIn...",
  "token_type": "bearer",
  "user_id": "usr_9a8b7c6d5e4f",
  "username": "admin",
  "role": "admin"
}
```

### `GET /api/v1/auth/me`
Retrieves the profile and role details of the current authenticated user.
- **Auth:** Any authenticated user
- **Response `200 OK`:**
```json
{
  "id": "usr_9a8b7c6d5e4f",
  "username": "admin",
  "email": "admin@sentinel-ai.local",
  "role": "admin",
  "is_active": true,
  "created_at": "2026-10-16T09:00:00Z"
}
```

---

## 3. Assessments

### `POST /api/v1/assessments`
Creates a new assessment with authorized scope bounds.
- **Auth:** Analyst or Admin
- **Request Body:**
```json
{
  "name": "Staging Web Assessment",
  "assessment_type": "web_application",
  "execution_mode": "demo",
  "targets": ["192.168.1.10:8080"],
  "excluded_targets": ["192.168.1.1"],
  "allowed_checks": ["reconnaissance", "vulnerability_analysis", "evidence_validation", "risk_assessment"],
  "scope_notes": "Internal lab validation only.",
  "authorization_confirmed": true
}
```
- **Response `201 Created`:**
```json
{
  "id": "asm_12345678",
  "name": "Staging Web Assessment",
  "assessment_type": "web_application",
  "execution_mode": "demo",
  "status": "pending_approval",
  "approval_status": false,
  "owner_id": "usr_9a8b7c6d5e4f",
  "created_at": "2026-10-16T09:20:00Z"
}
```

### `GET /api/v1/assessments`
Lists assessments accessible to the current user (paginated).
- **Query Params:** `page` (default 1), `page_size` (default 20), `status` (optional).
- **Auth:** Viewer, Analyst, or Admin

### `GET /api/v1/assessments/{assessment_id}`
Retrieves detailed status, scope, and agent execution stages for an assessment.
- **Auth:** Viewer, Analyst, or Admin (Ownership enforced)

### `POST /api/v1/assessments/{assessment_id}/approve`
Records human-in-the-loop authorization approval.
- **Auth:** Analyst or Admin
- **Response `200 OK`:**
```json
{
  "message": "Assessment approved successfully",
  "assessment_id": "asm_12345678",
  "approval_status": true
}
```

### `POST /api/v1/assessments/{assessment_id}/run`
Dispatches the 6-agent LangGraph workflow execution.
- **Auth:** Analyst or Admin
- **Response `202 Accepted`:**
```json
{
  "message": "Workflow started successfully",
  "assessment_id": "asm_12345678",
  "status": "running"
}
```

### `POST /api/v1/assessments/{assessment_id}/stop`
Requests safe cancellation of a running assessment workflow.
- **Auth:** Analyst or Admin
- **Response `200 OK`:**
```json
{
  "message": "Cancellation request submitted",
  "assessment_id": "asm_12345678"
}
```

---

## 4. Findings & Reports

### `GET /api/v1/assessments/{assessment_id}/findings`
Returns verified findings for an assessment, with optional severity filtering.
- **Query Params:** `severity` (`critical`, `high`, `medium`, `low`, `informational`), `page`, `page_size`.

### `GET /api/v1/assessments/{assessment_id}/report`
Returns the structured JSON report object conforming to `ReportSchema`.

### `GET /api/v1/assessments/{assessment_id}/report/html`
Returns the executive-ready, standalone sanitized HTML report.

---

## 5. Audit Logging

### `GET /api/v1/audit-logs`
Returns the immutable system audit trail (paginated).
- **Auth:** Admin Only
- **Response `200 OK`:**
```json
{
  "items": [
    {
      "id": "aud_883492",
      "timestamp": "2026-10-16T09:20:00Z",
      "action": "assessment_created",
      "user_id": "usr_9a8b7c6d5e4f",
      "resource_type": "assessment",
      "resource_id": "asm_12345678",
      "ip_address": "127.0.0.1",
      "details": { "name": "Staging Web Assessment" }
    }
  ],
  "total": 1,
  "page": 1,
  "page_size": 50,
  "pages": 1
}
```
