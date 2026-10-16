"""Pydantic schemas for request/response validation."""

from __future__ import annotations

from datetime import datetime
from typing import List, Optional, Any
from pydantic import BaseModel, Field, field_validator, model_validator

from app.models import (
    UserRole, AssessmentStatus, AssessmentType,
    ExecutionMode, Severity, Confidence, AgentStatus, AuditAction,
)


# ── Auth ─────────────────────────────────────────────────────────────

class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=100)
    password: str = Field(..., min_length=1, max_length=255)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserOut
    user_id: Optional[str] = None
    username: Optional[str] = None
    role: Optional[str] = None


class UserOut(BaseModel):
    id: str
    username: str
    email: str
    role: UserRole
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True


# ── Assessment ───────────────────────────────────────────────────────

class ScopeCreate(BaseModel):
    targets: List[str] = Field(..., min_length=1, max_length=20)
    excluded_targets: List[str] = Field(default_factory=list, max_length=20)
    allowed_checks: List[str] = Field(default_factory=list, max_length=20)
    notes: Optional[str] = Field(default="", max_length=2000)
    scope_notes: Optional[str] = Field(default="", max_length=2000)

    @field_validator("targets")
    @classmethod
    def validate_targets(cls, v: List[str]) -> List[str]:
        if not v:
            raise ValueError("At least one target is required")
        for t in v:
            if len(t) > 500:
                raise ValueError(f"Target too long: {t[:50]}...")
        return v

    @model_validator(mode="before")
    @classmethod
    def sync_notes(cls, data: Any) -> Any:
        if isinstance(data, dict):
            val = data.get("scope_notes") if data.get("scope_notes") is not None else data.get("notes")
            data["notes"] = val if val is not None else ""
            data["scope_notes"] = val if val is not None else ""
        return data


class AssessmentCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = Field(default=None, max_length=5000)
    assessment_type: AssessmentType
    execution_mode: ExecutionMode = ExecutionMode.DEMO
    authorization_confirmed: bool = Field(default=False)
    scope: Optional[ScopeCreate] = None
    targets: Optional[List[str]] = None
    excluded_targets: List[str] = Field(default_factory=list)
    allowed_checks: List[str] = Field(default_factory=list)
    scope_notes: Optional[str] = Field(default="")
    notes: Optional[str] = Field(default="")

    @model_validator(mode="before")
    @classmethod
    def assemble_scope(cls, data: Any) -> Any:
        if isinstance(data, dict):
            # Normalize execution_mode if sent as gemini_assisted
            mode_val = data.get("execution_mode")
            if mode_val in ("gemini_assisted", "gemini", "llm_assisted", "llm"):
                data["execution_mode"] = ExecutionMode.LLM_ASSISTED
            elif mode_val in ("demo", "demo_mode"):
                data["execution_mode"] = ExecutionMode.DEMO

            scope_val = data.get("scope")
            top_notes = data.get("scope_notes") if data.get("scope_notes") is not None else data.get("notes")
            if isinstance(scope_val, dict):
                if top_notes is not None and not scope_val.get("notes") and not scope_val.get("scope_notes"):
                    scope_val["notes"] = top_notes
                    scope_val["scope_notes"] = top_notes
            elif scope_val is None and data.get("targets"):
                data["scope"] = {
                    "targets": data.get("targets"),
                    "excluded_targets": data.get("excluded_targets", []),
                    "allowed_checks": data.get("allowed_checks", []),
                    "notes": top_notes or "",
                    "scope_notes": top_notes or "",
                }
            if data.get("scope"):
                if isinstance(data["scope"], dict):
                    data["scope_notes"] = data["scope"].get("scope_notes") or data["scope"].get("notes") or ""
                elif hasattr(data["scope"], "notes"):
                    data["scope_notes"] = getattr(data["scope"], "notes", "") or ""
        return data


class AssessmentApproveRequest(BaseModel):
    decision: str = Field(default="approved", max_length=50)
    reason: Optional[str] = Field(default="Scope and authorization reviewed and approved", max_length=1000)


class ScopeOut(BaseModel):
    id: str
    targets: List[str]
    excluded_targets: List[str]
    allowed_checks: List[str]
    notes: Optional[str] = ""
    scope_notes: Optional[str] = ""

    @model_validator(mode="before")
    @classmethod
    def sync_scope_out(cls, data: Any) -> Any:
        if isinstance(data, dict):
            val = data.get("scope_notes") if data.get("scope_notes") is not None else data.get("notes")
            data["notes"] = val if val is not None else ""
            data["scope_notes"] = val if val is not None else ""
        return data

    class Config:
        from_attributes = True


class AssessmentOut(BaseModel):
    id: str
    name: str
    description: Optional[str]
    assessment_type: AssessmentType
    execution_mode: ExecutionMode
    status: AssessmentStatus
    owner_id: str
    authorization_confirmed: bool
    approved_by: Optional[str]
    approved_at: Optional[datetime]
    approval_status: bool = False
    targets: List[str] = Field(default_factory=list)
    scope: Optional[ScopeOut] = None
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    error_message: Optional[str]
    created_at: datetime

    class Config:
        from_attributes = True

    @model_validator(mode="before")
    @classmethod
    def sync_assessment_targets(cls, data: Any) -> Any:
        if isinstance(data, dict):
            if "targets" not in data or not data["targets"]:
                scope_val = data.get("scope")
                if isinstance(scope_val, dict):
                    data["targets"] = scope_val.get("targets", [])
                elif hasattr(scope_val, "targets"):
                    data["targets"] = getattr(scope_val, "targets", [])
        return data


class AssessmentDetail(AssessmentOut):
    agent_executions: List[AgentExecutionOut] = []
    executions: List[AgentExecutionOut] = Field(default_factory=list)
    findings_count: int = 0

    @model_validator(mode="before")
    @classmethod
    def sync_executions(cls, data: Any) -> Any:
        if isinstance(data, dict):
            aes = data.get("agent_executions") or data.get("executions") or []
            data["agent_executions"] = aes
            data["executions"] = aes
        return data


# ── Agent Execution ──────────────────────────────────────────────────

class AgentExecutionOut(BaseModel):
    id: str
    agent_name: str
    step_order: int
    status: AgentStatus
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    input_summary: Optional[str]
    output_summary: Optional[str]
    error_message: Optional[str]
    execution_mode: ExecutionMode

    class Config:
        from_attributes = True


# ── Findings ─────────────────────────────────────────────────────────

class FindingOut(BaseModel):
    id: str
    assessment_id: str
    title: str
    description: str
    affected_asset: Optional[str] = None
    affected_port: Optional[str] = None
    severity: Severity
    risk_rating: Optional[str] = None
    confidence: Confidence
    validation_status: str
    scope_validation: Optional[str] = "AUTHORIZED"
    evidence: Optional[str] = None
    cwe_id: Optional[str] = None
    remediation: Optional[str] = None
    references: List[str] = Field(default_factory=list)
    source_type: str = "synthetic"
    originating_agent: Optional[str] = "Vulnerability Analysis Agent"
    is_duplicate: bool = False
    created_at: datetime

    class Config:
        from_attributes = True

    @model_validator(mode="before")
    @classmethod
    def populate_finding_fields(cls, data: Any) -> Any:
        if isinstance(data, dict):
            asset = data.get("affected_asset")
            if not data.get("affected_port") and asset and ":" in str(asset):
                data["affected_port"] = str(asset).split(":", 1)[1]
            if not data.get("risk_rating") and data.get("severity"):
                sev = data["severity"]
                data["risk_rating"] = sev.value.upper() if hasattr(sev, "value") else str(sev).upper()
            if not data.get("originating_agent"):
                data["originating_agent"] = "Vulnerability Analysis Agent"
            if not data.get("scope_validation"):
                data["scope_validation"] = "AUTHORIZED"
        return data


# ── Report ───────────────────────────────────────────────────────────

class ReportFinding(BaseModel):
    finding_id: str
    title: str
    description: str
    affected_asset: Optional[str] = None
    affected_port: Optional[str] = None
    severity: Severity
    risk_rating: Optional[str] = None
    confidence: Confidence
    validation_status: str
    scope_validation: Optional[str] = "AUTHORIZED"
    evidence: Optional[str] = None
    cwe_id: Optional[str] = None
    remediation: Optional[str] = None
    references: List[str] = Field(default_factory=list)
    source_type: str = "synthetic"
    originating_agent: Optional[str] = "Vulnerability Analysis Agent"
    detected_at: Optional[str] = None

    @model_validator(mode="before")
    @classmethod
    def populate_report_finding_fields(cls, data: Any) -> Any:
        if isinstance(data, dict):
            asset = data.get("affected_asset")
            if not data.get("affected_port") and asset and ":" in str(asset):
                data["affected_port"] = str(asset).split(":", 1)[1]
            if not data.get("risk_rating") and data.get("severity"):
                sev = data["severity"]
                data["risk_rating"] = sev.value.upper() if hasattr(sev, "value") else str(sev).upper()
            if not data.get("originating_agent"):
                data["originating_agent"] = "Vulnerability Analysis Agent"
            if not data.get("scope_validation"):
                data["scope_validation"] = "AUTHORIZED"
        return data


class SeveritySummary(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    informational: int = 0


class ReportSchema(BaseModel):
    assessment_id: str
    assessment_name: str
    assessment_mode: str
    scope: List[str]
    authorization_status: str
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    overall_status: str
    overall_risk: Optional[str] = "INFORMATIONAL"
    gemini_used: Optional[bool] = False
    gemini_model: Optional[str] = None
    executive_summary: str
    methodology: str
    findings: List[ReportFinding]
    severity_summary: SeveritySummary
    limitations: str
    remediation_priorities: List[str]
    generated_at: datetime


# ── Audit Log ────────────────────────────────────────────────────────

class AuditLogOut(BaseModel):
    id: str
    user_id: Optional[str]
    action: AuditAction
    resource_type: Optional[str]
    resource_id: Optional[str]
    details: Optional[dict]
    ip_address: Optional[str]
    timestamp: datetime

    class Config:
        from_attributes = True


# ── Pagination ───────────────────────────────────────────────────────

class PaginatedResponse(BaseModel):
    items: list
    total: int
    page: int
    page_size: int
    pages: int


# ── Health / Config ──────────────────────────────────────────────────

class HealthResponse(BaseModel):
    status: str
    version: str
    timestamp: datetime


class ConfigStatusResponse(BaseModel):
    gemini_configured: bool
    demo_mode: bool
    require_human_approval: bool
    database_type: str
    allowed_targets_count: int


# ── Error ────────────────────────────────────────────────────────────

class ErrorResponse(BaseModel):
    detail: str
    error_code: Optional[str] = None


# Fix forward reference
AssessmentDetail.model_rebuild()
