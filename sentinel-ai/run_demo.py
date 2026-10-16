#!/usr/bin/env python3
"""
SentinelAI — Standalone Multi-Agent Pipeline Demonstration

Executes the complete 6-agent penetration testing workflow end-to-end in offline demo mode.
Demonstrates:
  - Database initialization
  - RBAC and Scope Validation
  - LangGraph 6-Agent State Transitions
  - Anti-hallucination evidence validation
  - Deterministic risk assessment (CWE & CVSS)
  - Report artifact generation (JSON & Sanitized HTML)
"""

from __future__ import annotations

import asyncio
import os
import sys
import json
from datetime import datetime, timezone

# Ensure backend package is in python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "backend"))

from app.db.database import SessionLocal, init_db
from app.models import User, UserRole, Assessment, AssessmentStatus, Severity, Confidence
from app.security.auth import hash_password
from app.security.scope_validator import validate_scope
from app.workflows.orchestrator import run_assessment_workflow


def print_banner():
    banner = """
================================================================================
   ____             _   _            _    ___ 
  / ___|  ___ _ __ | |_(_)_ __   ___| |  / _ \\
  \\___ \\ / _ \\ '_ \\| __| | '_ \\ / _ \\ | | | | |
   ___) |  __/ | | | |_| | | | |  __/ | | |_| |
  |____/ \\___|_| |_|\\__|_|_| |_|\\___|_|  \\___/ 
  Agentic Multi-Agent Penetration Testing & Vulnerability Assessment
================================================================================
"""
    print(banner)


async def main():
    print_banner()
    print("[*] Phase 1: Initializing Local Database & Default Users...")
    init_db()
    db = SessionLocal()

    # Seed demo user
    user = db.query(User).filter(User.username == "analyst").first()
    if not user:
        user = User(
            username="analyst",
            email="analyst@sentinel-ai.local",
            hashed_password=hash_password("analyst123"),
            role=UserRole.ANALYST,
        )
        db.add(user)
        db.commit()
        db.refresh(user)
    print(f"    [+] Active User: {user.username} (Role: {user.role.value})")

    # Scope validation test
    print("\n[*] Phase 2: Testing Deterministic Scope Validator...")
    test_target = "192.168.1.10:8080"
    is_valid, errors = validate_scope(
        targets=[test_target],
        allowed_targets=["192.168.1.0/24", "10.0.0.0/8", "lab.local"],
    )
    if not is_valid:
        print(f"    [!] Scope validation failed: {'; '.join(errors)}")
        return
    print(f"    [+] Target '{test_target}' successfully validated within authorized CIDR 192.168.1.0/24.")

    # Create assessment
    asm = Assessment(
        name="Automated Demonstration Security Assessment",
        assessment_type="full",
        execution_mode="demo",
        status=AssessmentStatus.APPROVED,
        authorization_confirmed=True,
        approved_by=user.id,
        approved_at=datetime.now(timezone.utc),
        owner_id=user.id,
    )
    db.add(asm)
    db.commit()
    db.refresh(asm)
    print(f"    [+] Assessment created: {asm.id} (Status: {asm.status.value})")

    # Run Multi-Agent Orchestrator
    print("\n[*] Phase 3: Executing LangGraph Multi-Agent Workflow...")
    print("    Agents in pipeline:")
    print("      1. Scope & Planning Agent       -> Target boundary verification")
    print("      2. Reconnaissance Agent         -> Asset telemetry ingestion")
    print("      3. Vulnerability Analysis Agent -> Weakness correlation & CWE mapping")
    print("      4. Evidence Validation Agent    -> Anti-hallucination verification")
    print("      5. Risk Assessment Agent        -> Deterministic CVSS scoring")
    print("      6. Report Generation Agent      -> JSON and HTML artifact synthesis")
    print("\n    Dispatching state machine...")

    start_time = datetime.now()
    final_state = await run_assessment_workflow(
        assessment_id=asm.id,
        assessment_name=asm.name,
        assessment_type="web_application",
        execution_mode="demo",
        targets=[test_target],
        excluded_targets=["192.168.1.1"],
        allowed_checks=["reconnaissance", "vulnerability_analysis", "evidence_validation", "risk_assessment"],
        scope_notes="Offline standalone demonstration run",
        db_session=db,
    )
    duration = (datetime.now() - start_time).total_seconds()

    print(f"\n[+] Workflow Execution Completed in {duration:.2f}s!")
    print(f"    Workflow Status: {final_state.get('workflow_status')}")

    # Display Findings Table
    findings = final_state.get("risk_assessed_findings", [])
    print(f"\n[*] Phase 4: Validated Findings Summary ({len(findings)} findings recorded):")
    print("-" * 80)
    print(f"{'SEVERITY':<12} | {'CWE':<8} | {'CONFIDENCE':<10} | {'TITLE'}")
    print("-" * 80)
    for f in findings:
        sev = f.get("severity", "").upper()
        cwe = f.get("cwe_id", "-")
        conf = f.get("confidence", "")
        title = f.get("title", "")
        print(f"{sev:<12} | {cwe:<8} | {conf:<10} | {title}")
    print("-" * 80)

    # Save artifact outputs
    report_json = final_state.get("report_json", {})
    report_html = final_state.get("report_html", "")

    json_path = os.path.join(os.path.dirname(__file__), "sentinel_demo_report.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report_json, f, indent=2)

    html_path = os.path.join(os.path.dirname(__file__), "sentinel_demo_report.html")
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(report_html)

    print(f"\n[*] Phase 5: Deliverables Successfully Generated:")
    print(f"    [+] JSON Report: {json_path}")
    print(f"    [+] HTML Report: {html_path}")
    print("\n[OK] SentinelAI Demonstration Completed Successfully!")
    db.close()


if __name__ == "__main__":
    asyncio.run(main())
