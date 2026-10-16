"""API routes — all endpoints for SentinelAI."""

from __future__ import annotations

import math
import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status, Query, BackgroundTasks, Request, Body
from sqlalchemy.orm import Session, joinedload

from app.core.config import get_settings
from app.db.database import get_db
from app.models import (
    User, Assessment, AssessmentScope, Finding, AssessmentReport,
    AgentExecution, AuditLog, UserRole, AssessmentStatus, ExecutionMode,
    AuditAction, Severity, Confidence,
)
from app.schemas import (
    LoginRequest, TokenResponse, UserOut,
    AssessmentCreate, AssessmentOut, AssessmentDetail, ScopeOut,
    AssessmentApproveRequest,
    AgentExecutionOut, FindingOut,
    AuditLogOut, PaginatedResponse,
    HealthResponse, ConfigStatusResponse,
)
from app.security.auth import (
    hash_password, verify_password, needs_rehash, create_access_token,
    get_current_user, require_admin, require_analyst, require_viewer,
)
from app.security.scope_validator import validate_scope
from app.services.audit_service import log_audit_event
from app.workflows.orchestrator import run_assessment_workflow, cancel_assessment

logger = logging.getLogger("sentinel_ai.api")
settings = get_settings()

router = APIRouter()


# ════════════════════════════════════════════════════════════════
# Health & Config
# ════════════════════════════════════════════════════════════════

@router.get("/health", response_model=HealthResponse, tags=["System"])
async def health_check():
    """Application health check."""
    return HealthResponse(
        status="healthy",
        version="1.0.0",
        timestamp=datetime.now(timezone.utc),
    )


@router.get("/api/v1/config/status", response_model=ConfigStatusResponse, tags=["System"])
async def config_status(user: User = Depends(require_viewer)):
    """Safe configuration status — does not expose secrets."""
    db_type = "sqlite" if settings.database_url.startswith("sqlite") else "postgresql"
    return ConfigStatusResponse(
        gemini_configured=settings.is_gemini_configured,
        demo_mode=settings.is_demo_mode,
        require_human_approval=settings.require_human_approval,
        database_type=db_type,
        allowed_targets_count=len(settings.allowed_targets_list),
    )


# ════════════════════════════════════════════════════════════════
# Authentication
# ════════════════════════════════════════════════════════════════

@router.post("/api/v1/auth/login", response_model=TokenResponse, tags=["Auth"])
async def login(req: LoginRequest, request: Request, db: Session = Depends(get_db)):
    """Authenticate and receive a JWT token."""
    user = db.query(User).filter(User.username == req.username).first()
    if not user or not verify_password(req.password, user.hashed_password):
        log_audit_event(db, AuditAction.AUTH_FAILURE, details={"username": req.username},
                       ip_address=request.client.host if request.client else None)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account is disabled")

    # Seamless hash migration if work factor or scheme is updated
    if needs_rehash(user.hashed_password):
        user.hashed_password = hash_password(req.password)
        db.commit()

    token = create_access_token(user.id, user.role.value)
    log_audit_event(db, AuditAction.LOGIN, user_id=user.id,
                   ip_address=request.client.host if request.client else None)

    user_out = UserOut.model_validate(user)
    return TokenResponse(
        access_token=token,
        token_type="bearer",
        user=user_out,
        user_id=user.id,
        username=user.username,
        role=user.role.value if hasattr(user.role, "value") else str(user.role),
    )


@router.get("/api/v1/auth/me", response_model=UserOut, tags=["Auth"])
async def get_me(user: User = Depends(get_current_user)):
    """Get current authenticated user."""
    return UserOut.model_validate(user)


# ════════════════════════════════════════════════════════════════
# Assessments
# ════════════════════════════════════════════════════════════════

@router.post("/api/v1/assessments", response_model=AssessmentOut, status_code=status.HTTP_201_CREATED, tags=["Assessments"])
async def create_assessment(
    req: AssessmentCreate,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_analyst),
):
    """Create a new scoped assessment."""
    # Validate authorization confirmation
    if not req.authorization_confirmed:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Authorization must be confirmed before creating an assessment",
        )

    # Validate scope targets
    is_valid, errors = validate_scope(req.scope.targets)
    if not is_valid:
        log_audit_event(db, AuditAction.SCOPE_VIOLATION, user_id=user.id,
                       resource_type="assessment", details={"errors": errors},
                       ip_address=request.client.host if request.client else None)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Scope validation failed: {'; '.join(errors)}",
        )

    # Force demo mode if Gemini is not configured
    execution_mode = req.execution_mode
    if execution_mode in (ExecutionMode.LLM_ASSISTED, ExecutionMode.GEMINI_ASSISTED) and not settings.is_gemini_configured:
        execution_mode = ExecutionMode.DEMO

    # Determine initial status
    initial_status = AssessmentStatus.PENDING_APPROVAL if settings.require_human_approval else AssessmentStatus.APPROVED

    # Create assessment
    assessment = Assessment(
        name=req.name,
        description=req.description,
        assessment_type=req.assessment_type,
        execution_mode=execution_mode,
        status=initial_status,
        owner_id=user.id,
        authorization_confirmed=True,
    )
    db.add(assessment)
    db.flush()

    # Determine scope notes safely from req.scope or req.scope_notes
    notes_val = ""
    if req.scope and (req.scope.scope_notes or req.scope.notes):
        notes_val = req.scope.scope_notes or req.scope.notes or ""
    elif req.scope_notes:
        notes_val = req.scope_notes or ""

    # Create scope
    scope = AssessmentScope(
        assessment_id=assessment.id,
        targets=req.scope.targets,
        excluded_targets=req.scope.excluded_targets,
        allowed_checks=req.scope.allowed_checks,
        notes=notes_val,
    )
    db.add(scope)
    db.commit()
    db.refresh(assessment)

    log_audit_event(db, AuditAction.ASSESSMENT_CREATED, user_id=user.id,
                   resource_type="assessment", resource_id=assessment.id,
                   details={"name": req.name, "type": req.assessment_type.value},
                   ip_address=request.client.host if request.client else None)

    return AssessmentOut.model_validate(assessment)


@router.get("/api/v1/assessments", tags=["Assessments"])
async def list_assessments(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    db: Session = Depends(get_db),
    user: User = Depends(require_viewer),
):
    """List assessments accessible to the current user."""
    query = db.query(Assessment).options(joinedload(Assessment.scope))

    # Enforce ownership for non-admin users
    if user.role != UserRole.ADMIN:
        query = query.filter(Assessment.owner_id == user.id)

    total = query.count()
    items = (
        query.order_by(Assessment.created_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )

    return PaginatedResponse(
        items=[AssessmentOut.model_validate(a) for a in items],
        total=total,
        page=page,
        page_size=page_size,
        pages=math.ceil(total / page_size) if total > 0 else 0,
    )


@router.get("/api/v1/assessments/{assessment_id}", response_model=AssessmentDetail, tags=["Assessments"])
async def get_assessment(assessment_id: str, db: Session = Depends(get_db), user: User = Depends(require_viewer)):
    """Get assessment details including scope and agent executions."""
    assessment = _get_assessment_for_user(db, assessment_id, user)

    findings_count = db.query(Finding).filter(Finding.assessment_id == assessment_id).count()
    agent_executions = (
        db.query(AgentExecution)
        .filter(AgentExecution.assessment_id == assessment_id)
        .order_by(AgentExecution.step_order)
        .all()
    )

    base_dict = AssessmentOut.model_validate(assessment).model_dump()
    base_dict.pop("scope", None)
    detail = AssessmentDetail(
        **base_dict,
        scope=ScopeOut.model_validate(assessment.scope) if assessment.scope else None,
        agent_executions=[AgentExecutionOut.model_validate(ae) for ae in agent_executions],
        findings_count=findings_count,
    )
    return detail


@router.post("/api/v1/assessments/{assessment_id}/approve", response_model=AssessmentOut, tags=["Assessments"])
async def approve_assessment(
    assessment_id: str,
    request: Request,
    body: Optional[AssessmentApproveRequest] = Body(default=None),
    db: Session = Depends(get_db),
    user: User = Depends(require_analyst),
):
    """Record human approval for an assessment."""
    assessment = _get_assessment_for_user(db, assessment_id, user)

    # State machine check: must be pending_approval
    if assessment.status != AssessmentStatus.PENDING_APPROVAL:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Assessment is in '{assessment.status.value}' state, cannot approve",
        )

    # Authorization verification
    if not assessment.authorization_confirmed:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Assessment authorization has not been confirmed",
        )

    # Scope presence and validation
    if not assessment.scope or not assessment.scope.targets:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Assessment scope is missing or targets list is empty",
        )

    is_valid, errors = validate_scope(assessment.scope.targets)
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Scope validation failed: {'; '.join(errors)}",
        )

    decision_val = body.decision if body and body.decision else "approved"
    reason_val = body.reason if body and body.reason else "Scope and authorization reviewed and approved"

    now = datetime.now(timezone.utc)
    assessment.status = AssessmentStatus.APPROVED
    assessment.approved_by = user.id
    assessment.approved_at = now
    db.commit()
    db.refresh(assessment)

    log_audit_event(
        db,
        AuditAction.ASSESSMENT_APPROVED,
        user_id=user.id,
        resource_type="assessment",
        resource_id=assessment_id,
        details={
            "approver_id": user.id,
            "approver_username": user.username,
            "approved_at": now.isoformat(),
            "decision": decision_val,
            "reason": reason_val,
            "target_count": len(assessment.scope.targets) if assessment.scope and assessment.scope.targets else 0,
        },
        ip_address=request.client.host if request.client else None,
    )

    return AssessmentOut.model_validate(assessment)


@router.post("/api/v1/assessments/{assessment_id}/run", response_model=AssessmentOut, tags=["Assessments"])
async def run_assessment(
    assessment_id: str,
    request: Request,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    user: User = Depends(require_analyst),
):
    """Execute the multi-agent assessment workflow."""
    assessment = _get_assessment_for_user(db, assessment_id, user)

    if assessment.status not in (AssessmentStatus.APPROVED, AssessmentStatus.DRAFT):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Assessment must be approved before running (current: {assessment.status.value})",
        )

    if settings.require_human_approval and assessment.status != AssessmentStatus.APPROVED:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Human approval is required before running this assessment",
        )

    # Mark as running
    assessment.status = AssessmentStatus.RUNNING
    assessment.started_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(assessment)

    log_audit_event(db, AuditAction.ASSESSMENT_STARTED, user_id=user.id,
                   resource_type="assessment", resource_id=assessment_id,
                   ip_address=request.client.host if request.client else None)

    # Run workflow in background
    background_tasks.add_task(
        _run_workflow_background,
        assessment_id=assessment.id,
        assessment_name=assessment.name,
        assessment_type=assessment.assessment_type.value,
        execution_mode=assessment.execution_mode.value,
        targets=assessment.scope.targets if assessment.scope else [],
        excluded_targets=assessment.scope.excluded_targets if assessment.scope else [],
        allowed_checks=assessment.scope.allowed_checks if assessment.scope else [],
        scope_notes=assessment.scope.notes if assessment.scope else None,
        user_id=user.id,
    )

    return AssessmentOut.model_validate(assessment)


@router.post("/api/v1/assessments/{assessment_id}/stop", response_model=AssessmentOut, tags=["Assessments"])
async def stop_assessment(
    assessment_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_analyst),
):
    """Request safe cancellation of a running assessment."""
    assessment = _get_assessment_for_user(db, assessment_id, user)

    if assessment.status != AssessmentStatus.RUNNING:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Assessment is not currently running",
        )

    cancelled = cancel_assessment(assessment_id)
    if cancelled:
        assessment.status = AssessmentStatus.CANCELLED
        assessment.completed_at = datetime.now(timezone.utc)
        db.commit()
        db.refresh(assessment)

        log_audit_event(db, AuditAction.ASSESSMENT_CANCELLED, user_id=user.id,
                       resource_type="assessment", resource_id=assessment_id,
                       ip_address=request.client.host if request.client else None)

    return AssessmentOut.model_validate(assessment)


@router.get("/api/v1/assessments/{assessment_id}/findings", tags=["Assessments"])
async def get_findings(
    assessment_id: str,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=100),
    severity: Optional[str] = Query(default=None),
    db: Session = Depends(get_db),
    user: User = Depends(require_viewer),
):
    """Get findings for an assessment."""
    _get_assessment_for_user(db, assessment_id, user)  # ownership check

    query = db.query(Finding).filter(Finding.assessment_id == assessment_id)
    if severity:
        try:
            sev_enum = Severity(severity.lower())
            query = query.filter(Finding.severity == sev_enum)
        except ValueError:
            pass

    total = query.count()
    items = (
        query.order_by(Finding.severity, Finding.created_at)
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )

    return PaginatedResponse(
        items=[FindingOut.model_validate(f) for f in items],
        total=total,
        page=page,
        page_size=page_size,
        pages=math.ceil(total / page_size) if total > 0 else 0,
    )


@router.get("/api/v1/assessments/{assessment_id}/report", tags=["Assessments"])
async def get_report(
    assessment_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_viewer),
):
    """Get the structured JSON report."""
    assessment = _get_assessment_for_user(db, assessment_id, user)

    report = db.query(AssessmentReport).filter(AssessmentReport.assessment_id == assessment_id).first()
    if not report:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not yet generated")

    log_audit_event(db, AuditAction.REPORT_ACCESSED, user_id=user.id,
                   resource_type="report", resource_id=assessment_id,
                   ip_address=request.client.host if request.client else None)

    return report.report_json


@router.get("/api/v1/assessments/{assessment_id}/report/html", tags=["Assessments"])
async def get_report_html(
    assessment_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_viewer),
):
    """Get the HTML report."""
    from fastapi.responses import HTMLResponse

    assessment = _get_assessment_for_user(db, assessment_id, user)

    report = db.query(AssessmentReport).filter(AssessmentReport.assessment_id == assessment_id).first()
    if not report or (not report.report_html and not report.report_json):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="HTML report not yet generated")

    log_audit_event(db, AuditAction.REPORT_ACCESSED, user_id=user.id,
                   resource_type="report_html", resource_id=assessment_id,
                   ip_address=request.client.host if request.client else None)

    if report.report_json and isinstance(report.report_json, dict):
        from app.agents.report_agent import _generate_html_report
        report_data = dict(report.report_json)
        if not report_data.get("scope"):
            report_data["scope"] = assessment.targets
        return HTMLResponse(content=_generate_html_report(report_data))

    return HTMLResponse(content=report.report_html)


# ════════════════════════════════════════════════════════════════
# Audit Logs
# ════════════════════════════════════════════════════════════════

@router.get("/api/v1/audit-logs", tags=["Audit"])
async def get_audit_logs(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=100),
    db: Session = Depends(get_db),
    user: User = Depends(require_admin),
):
    """Get audit logs (admin only)."""
    query = db.query(AuditLog)
    total = query.count()
    items = (
        query.order_by(AuditLog.timestamp.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )

    return PaginatedResponse(
        items=[AuditLogOut.model_validate(log) for log in items],
        total=total,
        page=page,
        page_size=page_size,
        pages=math.ceil(total / page_size) if total > 0 else 0,
    )


# ════════════════════════════════════════════════════════════════
# Helpers
# ════════════════════════════════════════════════════════════════

def _get_assessment_for_user(db: Session, assessment_id: str, user: User) -> Assessment:
    """Fetch an assessment with ownership enforcement."""
    assessment = db.query(Assessment).filter(Assessment.id == assessment_id).first()
    if not assessment:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Assessment not found")

    if user.role != UserRole.ADMIN and assessment.owner_id != user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")

    return assessment


async def _run_workflow_background(
    assessment_id: str,
    assessment_name: str,
    assessment_type: str,
    execution_mode: str,
    targets: list,
    excluded_targets: list,
    allowed_checks: list,
    scope_notes: Optional[str],
    user_id: str,
):
    """Background task to run the assessment workflow."""
    from app.db.database import SessionLocal

    db = SessionLocal()
    try:
        final_state = await run_assessment_workflow(
            assessment_id=assessment_id,
            assessment_name=assessment_name,
            assessment_type=assessment_type,
            execution_mode=execution_mode,
            targets=targets,
            excluded_targets=excluded_targets,
            allowed_checks=allowed_checks,
            scope_notes=scope_notes,
            db_session=db,
        )

        # Persist findings
        assessment = db.query(Assessment).filter(Assessment.id == assessment_id).first()
        if not assessment:
            return

        workflow_status = final_state.get("workflow_status", "failed")

        if workflow_status == "completed":
            # Clean up any existing findings and report to support safe retries
            db.query(Finding).filter(Finding.assessment_id == assessment_id).delete()
            db.query(AssessmentReport).filter(AssessmentReport.assessment_id == assessment_id).delete()

            # Store findings: check risk_assessed_findings, report_json['findings'], or validated_findings
            findings_data = (
                final_state.get("risk_assessed_findings")
                or (final_state.get("report_json", {}).get("findings") if isinstance(final_state.get("report_json"), dict) else [])
                or final_state.get("validated_findings")
                or final_state.get("raw_findings")
                or []
            )

            for i, f in enumerate(findings_data):
                sev_val = str(f.get("severity", "informational")).lower()
                try:
                    sev_enum = Severity(sev_val)
                except ValueError:
                    sev_enum = Severity.INFORMATIONAL

                conf_val = str(f.get("confidence", "unverified")).lower()
                try:
                    conf_enum = Confidence(conf_val)
                except ValueError:
                    conf_enum = Confidence.UNVERIFIED

                finding = Finding(
                    assessment_id=assessment_id,
                    title=f.get("title", "Untitled"),
                    description=f.get("description", ""),
                    affected_asset=f.get("affected_asset"),
                    severity=sev_enum,
                    confidence=conf_enum,
                    validation_status=f.get("validation_status", "unverified"),
                    evidence=f.get("evidence"),
                    cwe_id=f.get("cwe_id"),
                    remediation=f.get("remediation"),
                    references=f.get("references", []),
                    source_type=f.get("source_type", "synthetic"),
                    is_duplicate=f.get("is_duplicate", False),
                )
                db.add(finding)

            # Store report
            report = AssessmentReport(
                assessment_id=assessment_id,
                report_json=final_state.get("report_json"),
                report_html=final_state.get("report_html"),
                executive_summary=final_state.get("executive_summary"),
                methodology=final_state.get("methodology"),
                limitations=final_state.get("report_limitations"),
            )
            db.add(report)

            assessment.status = AssessmentStatus.COMPLETED
            assessment.completed_at = datetime.now(timezone.utc)

            log_audit_event(db, AuditAction.ASSESSMENT_COMPLETED, user_id=user_id,
                           resource_type="assessment", resource_id=assessment_id)
            log_audit_event(db, AuditAction.REPORT_GENERATED, user_id=user_id,
                           resource_type="report", resource_id=assessment_id)

        elif workflow_status == "cancelled":
            assessment.status = AssessmentStatus.CANCELLED
            assessment.completed_at = datetime.now(timezone.utc)

        else:
            assessment.status = AssessmentStatus.FAILED
            assessment.error_message = "; ".join(final_state.get("errors", ["Unknown error"]))
            assessment.completed_at = datetime.now(timezone.utc)

            log_audit_event(db, AuditAction.ASSESSMENT_FAILED, user_id=user_id,
                           resource_type="assessment", resource_id=assessment_id,
                           details={"errors": final_state.get("errors", [])})

        db.commit()

    except Exception as e:
        logger.error("Background workflow failed for %s: %s", assessment_id, str(e))
        try:
            assessment = db.query(Assessment).filter(Assessment.id == assessment_id).first()
            if assessment:
                assessment.status = AssessmentStatus.FAILED
                assessment.error_message = str(e)
                assessment.completed_at = datetime.now(timezone.utc)
                db.commit()
        except Exception:
            pass
    finally:
        db.close()
