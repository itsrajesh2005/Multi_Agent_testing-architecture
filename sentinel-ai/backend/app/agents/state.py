"""
LangGraph state definition for the multi-agent assessment workflow.
All agents read from and write to this shared typed state.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, TypedDict


class AssessmentState(TypedDict, total=False):
    """Shared state passed between all agents in the LangGraph workflow."""

    # ── Input (set before workflow starts) ──
    assessment_id: str
    assessment_name: str
    assessment_type: str  # full, reconnaissance, vulnerability_scan, configuration_review
    execution_mode: str   # demo or llm_assisted
    targets: List[str]
    excluded_targets: List[str]
    allowed_checks: List[str]
    scope_notes: Optional[str]

    # ── Agent 1: Scope & Planning ──
    plan: Optional[Dict[str, Any]]
    plan_steps: List[Dict[str, Any]]
    plan_limitations: List[str]
    plan_expected_outputs: List[str]

    # ── Agent 2: Reconnaissance ──
    recon_observations: List[Dict[str, Any]]
    recon_missing_info: List[str]

    # ── Agent 3: Vulnerability Analysis ──
    raw_findings: List[Dict[str, Any]]

    # ── Agent 4: Evidence Validation ──
    validated_findings: List[Dict[str, Any]]
    duplicates_found: int
    contradictions: List[str]
    missing_evidence: List[str]

    # ── Agent 5: Risk Assessment ──
    risk_assessed_findings: List[Dict[str, Any]]
    overall_risk: str
    remediation_priorities: List[str]

    # ── Agent 6: Report Generation ──
    executive_summary: str
    methodology: str
    report_limitations: str
    report_json: Optional[Dict[str, Any]]
    report_html: Optional[str]

    # ── AI & Engine Metadata ──
    gemini_used: bool
    gemini_model: Optional[str]
    ai_engine_metadata: Dict[str, Any]

    # ── Control ──
    current_agent: str
    errors: List[str]
    is_cancelled: bool
    workflow_status: str  # running, completed, failed, cancelled
