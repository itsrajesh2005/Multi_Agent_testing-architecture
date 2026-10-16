"""Audit logging service — records security-relevant events."""

from __future__ import annotations

import logging
from typing import Optional

from sqlalchemy.orm import Session

from app.models import AuditLog, AuditAction

logger = logging.getLogger("sentinel_ai.audit")


def log_audit_event(
    db: Session,
    action: AuditAction,
    user_id: Optional[str] = None,
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    details: Optional[dict] = None,
    ip_address: Optional[str] = None,
) -> AuditLog:
    """Create an audit log entry and commit it."""
    # Sanitize details — never log secrets
    if details:
        def _sanitize(val):
            sensitive_keys = {"password", "token", "api_key", "secret", "credential", "auth", "jwt", "private_key"}
            if isinstance(val, dict):
                return {
                    k: ("***REDACTED***" if any(s in str(k).lower() for s in sensitive_keys) else _sanitize(v))
                    for k, v in val.items()
                }
            elif isinstance(val, list):
                return [_sanitize(x) for x in val]
            return val

        details = _sanitize(details)

    entry = AuditLog(
        user_id=user_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        details=details,
        ip_address=ip_address,
    )
    db.add(entry)
    db.commit()
    db.refresh(entry)

    logger.info(
        "AUDIT: action=%s user=%s resource=%s/%s",
        action.value,
        user_id or "system",
        resource_type or "-",
        resource_id or "-",
    )
    return entry
