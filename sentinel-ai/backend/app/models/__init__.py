"""SQLAlchemy ORM models for SentinelAI."""

from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import (
    Column, String, Text, DateTime, Boolean, Integer,
    ForeignKey, Enum as SAEnum, Index, JSON,
)
from sqlalchemy.orm import relationship

from app.db.database import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _new_id() -> str:
    return uuid.uuid4().hex


# ── Enums ────────────────────────────────────────────────────────────

class UserRole(str, enum.Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


class AssessmentStatus(str, enum.Enum):
    DRAFT = "draft"
    PENDING_APPROVAL = "pending_approval"
    APPROVED = "approved"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class AssessmentType(str, enum.Enum):
    FULL = "full"
    RECONNAISSANCE = "reconnaissance"
    VULNERABILITY_SCAN = "vulnerability_scan"
    CONFIGURATION_REVIEW = "configuration_review"
    WEB_APPLICATION = "web_application"
    API_SECURITY = "api_security"
    NETWORK_SERVICE = "network_service"
    CONFIGURATION_AUDIT = "configuration_audit"


class ExecutionMode(str, enum.Enum):
    DEMO = "demo"
    LLM_ASSISTED = "llm_assisted"
    GEMINI_ASSISTED = "gemini_assisted"


class Severity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class Confidence(str, enum.Enum):
    CONFIRMED = "confirmed"
    SUSPECTED = "suspected"
    UNVERIFIED = "unverified"


class AgentStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class AuditAction(str, enum.Enum):
    LOGIN = "login"
    LOGOUT = "logout"
    ASSESSMENT_CREATED = "assessment_created"
    ASSESSMENT_APPROVED = "assessment_approved"
    ASSESSMENT_STARTED = "assessment_started"
    ASSESSMENT_COMPLETED = "assessment_completed"
    ASSESSMENT_FAILED = "assessment_failed"
    ASSESSMENT_CANCELLED = "assessment_cancelled"
    REPORT_ACCESSED = "report_accessed"
    REPORT_GENERATED = "report_generated"
    FINDING_CREATED = "finding_created"
    SCOPE_VIOLATION = "scope_violation"
    AUTH_FAILURE = "auth_failure"


# ── Models ───────────────────────────────────────────────────────────

class User(Base):
    __tablename__ = "users"

    id = Column(String(32), primary_key=True, default=_new_id)
    username = Column(String(100), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    role = Column(SAEnum(UserRole), nullable=False, default=UserRole.ANALYST)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)

    assessments = relationship(
        "Assessment",
        foreign_keys="Assessment.owner_id",
        back_populates="owner",
        lazy="dynamic",
    )
    approved_assessments = relationship(
        "Assessment",
        foreign_keys="Assessment.approved_by",
        back_populates="approver",
        lazy="dynamic",
    )
    audit_logs = relationship(
        "AuditLog",
        foreign_keys="AuditLog.user_id",
        back_populates="user",
        lazy="dynamic",
    )


class Assessment(Base):
    __tablename__ = "assessments"

    id = Column(String(32), primary_key=True, default=_new_id)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    assessment_type = Column(SAEnum(AssessmentType), nullable=False)
    execution_mode = Column(SAEnum(ExecutionMode), nullable=False, default=ExecutionMode.DEMO)
    status = Column(SAEnum(AssessmentStatus), nullable=False, default=AssessmentStatus.DRAFT)
    owner_id = Column(String(32), ForeignKey("users.id"), nullable=False, index=True)
    authorization_confirmed = Column(Boolean, default=False, nullable=False)
    approved_by = Column(String(32), ForeignKey("users.id"), nullable=True)
    approved_at = Column(DateTime(timezone=True), nullable=True)
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    error_message = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)

    owner = relationship("User", foreign_keys=[owner_id], back_populates="assessments")
    approver = relationship("User", foreign_keys=[approved_by], back_populates="approved_assessments")
    scope = relationship("AssessmentScope", back_populates="assessment", uselist=False, cascade="all, delete-orphan")
    agent_executions = relationship("AgentExecution", back_populates="assessment", cascade="all, delete-orphan",
                                   order_by="AgentExecution.step_order")
    findings = relationship("Finding", back_populates="assessment", cascade="all, delete-orphan")
    report = relationship("AssessmentReport", back_populates="assessment", uselist=False, cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_assessments_status", "status"),
        Index("ix_assessments_owner_status", "owner_id", "status"),
    )

    @property
    def approval_status(self) -> bool:
        """Helper property indicating whether human approval has been granted."""
        return self.status == AssessmentStatus.APPROVED or bool(self.approved_at)

    @property
    def targets(self) -> list:
        """Helper property exposing the target list from the assessment's scope."""
        if self.scope and self.scope.targets:
            return self.scope.targets
        return []


class AssessmentScope(Base):
    __tablename__ = "assessment_scopes"

    id = Column(String(32), primary_key=True, default=_new_id)
    assessment_id = Column(String(32), ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False, unique=True)
    targets = Column(JSON, nullable=False, default=list)  # list of target strings
    excluded_targets = Column(JSON, nullable=True, default=list)
    allowed_checks = Column(JSON, nullable=True, default=list)
    notes = Column(Text, nullable=True)

    assessment = relationship("Assessment", back_populates="scope")

    @property
    def scope_notes(self) -> Optional[str]:
        """Alias property matching scope_notes to the underlying notes column."""
        return self.notes or ""

    @scope_notes.setter
    def scope_notes(self, value: Optional[str]) -> None:
        self.notes = value


class AgentExecution(Base):
    __tablename__ = "agent_executions"

    id = Column(String(32), primary_key=True, default=_new_id)
    assessment_id = Column(String(32), ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False, index=True)
    agent_name = Column(String(100), nullable=False)
    step_order = Column(Integer, nullable=False)
    status = Column(SAEnum(AgentStatus), nullable=False, default=AgentStatus.PENDING)
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    input_summary = Column(Text, nullable=True)
    output_summary = Column(Text, nullable=True)
    output_data = Column(JSON, nullable=True)
    error_message = Column(Text, nullable=True)
    execution_mode = Column(SAEnum(ExecutionMode), nullable=False, default=ExecutionMode.DEMO)

    assessment = relationship("Assessment", back_populates="agent_executions")

    __table_args__ = (
        Index("ix_agent_exec_assessment_step", "assessment_id", "step_order"),
    )


class Finding(Base):
    __tablename__ = "findings"

    id = Column(String(32), primary_key=True, default=_new_id)
    assessment_id = Column(String(32), ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False, index=True)
    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=False)
    affected_asset = Column(String(500), nullable=True)
    severity = Column(SAEnum(Severity), nullable=False, default=Severity.INFORMATIONAL)
    confidence = Column(SAEnum(Confidence), nullable=False, default=Confidence.UNVERIFIED)
    validation_status = Column(String(50), nullable=False, default="unverified")
    evidence = Column(Text, nullable=True)
    cwe_id = Column(String(20), nullable=True)
    remediation = Column(Text, nullable=True)
    references = Column(JSON, nullable=True, default=list)
    source_type = Column(String(50), nullable=False, default="synthetic")  # synthetic, static_analysis, supplied_evidence
    is_duplicate = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)

    assessment = relationship("Assessment", back_populates="findings")

    @property
    def affected_port(self) -> Optional[str]:
        if self.affected_asset and ":" in str(self.affected_asset):
            return str(self.affected_asset).split(":", 1)[1]
        return None

    @property
    def risk_rating(self) -> str:
        return self.severity.value.upper() if self.severity else "INFORMATIONAL"

    @property
    def originating_agent(self) -> str:
        return "Vulnerability Analysis Agent"

    @property
    def scope_validation(self) -> str:
        if self.assessment and self.assessment.scope and self.assessment.scope.targets:
            from app.agents.report_agent import check_asset_target_mapping
            is_mapped, _ = check_asset_target_mapping(self.affected_asset, self.assessment.scope.targets)
            return "AUTHORIZED" if is_mapped else "OUT_OF_SCOPE"
        return "AUTHORIZED"

    __table_args__ = (
        Index("ix_findings_severity", "severity"),
        Index("ix_findings_assessment_severity", "assessment_id", "severity"),
    )


class AssessmentReport(Base):
    __tablename__ = "assessment_reports"

    id = Column(String(32), primary_key=True, default=_new_id)
    assessment_id = Column(String(32), ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False, unique=True)
    report_json = Column(JSON, nullable=True)
    report_html = Column(Text, nullable=True)
    executive_summary = Column(Text, nullable=True)
    methodology = Column(Text, nullable=True)
    limitations = Column(Text, nullable=True)
    generated_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)

    assessment = relationship("Assessment", back_populates="report")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(String(32), primary_key=True, default=_new_id)
    user_id = Column(String(32), ForeignKey("users.id"), nullable=True, index=True)
    action = Column(SAEnum(AuditAction), nullable=False)
    resource_type = Column(String(100), nullable=True)
    resource_id = Column(String(32), nullable=True)
    details = Column(JSON, nullable=True)
    ip_address = Column(String(45), nullable=True)
    timestamp = Column(DateTime(timezone=True), default=_utcnow, nullable=False, index=True)

    user = relationship("User", foreign_keys=[user_id], back_populates="audit_logs")

    __table_args__ = (
        Index("ix_audit_logs_action", "action"),
        Index("ix_audit_logs_resource", "resource_type", "resource_id"),
    )
