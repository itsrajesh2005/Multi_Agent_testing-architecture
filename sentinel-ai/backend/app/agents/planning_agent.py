"""
Agent 1 — Scope and Planning Agent

Validates the assessment request, creates a structured plan,
identifies required evidence and permitted checks, and rejects
out-of-scope requests. Authorization is enforced deterministically.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict

from app.agents.state import AssessmentState
from app.services.gemini_provider import get_llm_provider, GeminiProviderError

logger = logging.getLogger("sentinel_ai.agents.planning")

# Deterministic: assessment types and their allowed checks
ALLOWED_ASSESSMENT_CHECKS = {
    "full": [
        "asset_discovery", "configuration_review", "dependency_audit",
        "access_control_review", "network_segmentation", "tls_review",
        "header_analysis", "error_handling_review",
    ],
    "reconnaissance": [
        "asset_discovery", "technology_fingerprint", "network_mapping",
    ],
    "vulnerability_scan": [
        "dependency_audit", "configuration_review", "tls_review",
        "header_analysis",
    ],
    "configuration_review": [
        "configuration_review", "access_control_review", "tls_review",
        "header_analysis", "error_handling_review",
    ],
    "web_application": [
        "reconnaissance", "vulnerability_analysis", "evidence_validation",
        "risk_assessment", "asset_discovery", "header_analysis", "tls_review",
    ],
    "api_security": [
        "reconnaissance", "vulnerability_analysis", "evidence_validation",
        "risk_assessment", "access_control_review", "header_analysis",
    ],
    "network_service": [
        "reconnaissance", "vulnerability_analysis", "evidence_validation",
        "risk_assessment", "asset_discovery", "network_mapping",
    ],
    "configuration_audit": [
        "reconnaissance", "vulnerability_analysis", "evidence_validation",
        "risk_assessment", "configuration_review", "dependency_audit",
    ],
}


async def planning_agent(state: AssessmentState) -> Dict[str, Any]:
    """
    Scope & Planning Agent node for LangGraph.

    - Validates assessment type against allowed options (deterministic)
    - Creates structured assessment plan
    - Identifies required evidence and permitted checks
    - Rejects out-of-scope requests
    """
    logger.info("Agent 1 (Planning) starting for assessment %s", state.get("assessment_id"))

    assessment_type = state.get("assessment_type", "full")
    targets = state.get("targets", [])
    execution_mode = state.get("execution_mode", "demo")

    # ── Deterministic validation ──
    if assessment_type not in ALLOWED_ASSESSMENT_CHECKS:
        return {
            "plan": None,
            "plan_steps": [],
            "plan_limitations": [f"Unknown assessment type: {assessment_type}"],
            "plan_expected_outputs": [],
            "current_agent": "planning",
            "errors": [f"Invalid assessment type: {assessment_type}"],
            "workflow_status": "failed",
        }

    excluded_targets = state.get("excluded_targets", [])
    excluded_set = set(t.strip().lower() for t in (excluded_targets or []))
    sanitized_targets = [t for t in targets if t.strip().lower() not in excluded_set]

    if not sanitized_targets:
        return {
            "plan": None,
            "plan_steps": [],
            "plan_limitations": ["All requested targets are in the exclusion list"],
            "plan_expected_outputs": [],
            "current_agent": "planning",
            "errors": ["All requested targets are excluded from the assessment scope"],
            "workflow_status": "failed",
        }

    allowed_checks = ALLOWED_ASSESSMENT_CHECKS[assessment_type]

    # Filter user-specified checks against allowed list
    user_checks = state.get("allowed_checks", [])
    if user_checks:
        validated_checks = [c for c in user_checks if c in allowed_checks]
        if not validated_checks:
            validated_checks = allowed_checks  # fallback to all allowed
    else:
        validated_checks = allowed_checks

    # ── Build plan (LLM-assisted or deterministic) ──
    provider = get_llm_provider()
    plan_data = None
    scope_notes = state.get("scope_notes") or ""
    gemini_used = False
    gemini_model = None

    try:
        scope_notes_clause = f"Scope Notes / Restrictions: {scope_notes}\n" if scope_notes else ""
        prompt = (
            f"Create a security assessment plan for the following scope:\n"
            f"Assessment Type: {assessment_type}\n"
            f"Targets: {', '.join(sanitized_targets)}\n"
            f"Excluded Targets (STRICTLY PROHIBITED): {', '.join(excluded_targets) if excluded_targets else 'None'}\n"
            f"Permitted Checks: {', '.join(validated_checks)}\n"
            f"{scope_notes_clause}"
            f"Execution Mode: {execution_mode}\n\n"
            f"Respond with a JSON object containing: plan_id, steps (list of step objects "
            f"with step number, name, description), limitations, and expected_outputs."
        )
        raw = await provider.generate(prompt)
        try:
            plan_data = json.loads(raw) if raw.startswith("{") else json.loads(
                raw.split("```json")[-1].split("```")[0] if "```json" in raw else raw
            )
            if getattr(provider, "last_used_model", None):
                gemini_used = True
                gemini_model = provider.last_used_model
        except json.JSONDecodeError:
            logger.warning("Could not parse LLM plan response as JSON, using deterministic plan")
            plan_data = None
    except GeminiProviderError as e:
        logger.warning("LLM unavailable for planning, using deterministic plan: %s", e)

    # Deterministic fallback plan
    if plan_data is None:
        plan_data = {
            "plan_id": f"plan-{state.get('assessment_id', 'unknown')[:8]}",
            "assessment_type": assessment_type,
            "mode": execution_mode,
            "scope_notes": scope_notes,
            "targets": sanitized_targets,
            "excluded_targets": excluded_targets,
        }

    steps = plan_data.get("steps", [])
    if not steps:
        steps = [
            {"step": i + 1, "name": check.replace("_", " ").title(), "description": f"Perform {check} analysis"}
            for i, check in enumerate(validated_checks)
        ]

    limitations = plan_data.get("limitations", [])
    if excluded_targets:
        limitations.append(f"Excluded targets strictly prohibited from testing: {', '.join(excluded_targets)}")
    if execution_mode == "demo":
        limitations.append("Demo mode — analysis uses synthetic evidence only")
        limitations.append("No live network scanning performed")

    expected_outputs = plan_data.get("expected_outputs", ["findings_list", "risk_assessment", "report"])

    logger.info("Agent 1 (Planning) completed: %d steps, %d limitations (Gemini used: %s)",
                len(steps), len(limitations), gemini_used)

    res = {
        "plan": plan_data,
        "plan_steps": steps,
        "plan_limitations": limitations,
        "plan_expected_outputs": expected_outputs,
        "current_agent": "planning",
        "errors": [],
    }
    if gemini_used:
        res["gemini_used"] = True
        res["gemini_model"] = gemini_model
    return res
