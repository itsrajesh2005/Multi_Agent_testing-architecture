"""
Agent 4 — Evidence Validation Agent

Checks whether each finding is supported by available evidence.
Detects duplicates and contradictions. Labels results as
confirmed, suspected, or unverified. Reduces false positives.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List

from app.agents.state import AssessmentState
from app.services.gemini_provider import get_llm_provider, GeminiProviderError

logger = logging.getLogger("sentinel_ai.agents.validation")


async def validation_agent(state: AssessmentState) -> Dict[str, Any]:
    """
    Evidence Validation Agent node for LangGraph.

    - Validates each finding against available evidence
    - Detects duplicates
    - Identifies contradictions
    - Labels confidence levels
    """
    logger.info("Agent 4 (Validation) starting for assessment %s", state.get("assessment_id"))

    raw_findings = state.get("raw_findings", [])
    recon_observations = state.get("recon_observations", [])
    execution_mode = state.get("execution_mode", "demo")

    if not raw_findings:
        logger.warning("No findings to validate")
        return {
            "validated_findings": [],
            "duplicates_found": 0,
            "contradictions": [],
            "missing_evidence": ["No findings provided for validation"],
            "current_agent": "validation",
        }

    targets = state.get("targets", [])
    excluded_targets = state.get("excluded_targets", [])

    # ── Step 1: Deterministic duplicate detection ──
    seen_titles = {}
    unique_findings = []
    duplicates = 0

    for finding in raw_findings:
        title = finding.get("title", "").lower().strip()
        asset = finding.get("affected_asset", "").lower().strip()
        key = f"{title}||{asset}"

        if key in seen_titles:
            duplicates += 1
            finding["is_duplicate"] = True
            logger.info("Duplicate finding detected: %s on %s", title, asset)
        else:
            seen_titles[key] = True
            finding["is_duplicate"] = False
            unique_findings.append(finding)

    # ── Step 2: Scope enforcement & evidence validation ──
    from app.agents.report_agent import check_asset_target_mapping

    validated = []
    missing_evidence: List[str] = []
    contradictions: List[str] = []

    for finding in unique_findings:
        asset = finding.get("affected_asset")
        evidence = finding.get("evidence", "")
        source_type = finding.get("source_type", "unknown")

        # Extract port if present
        if asset and ":" in str(asset):
            finding["affected_port"] = str(asset).split(":", 1)[1]
        else:
            finding["affected_port"] = None

        # Check exclusion first
        is_excluded = False
        if asset and excluded_targets:
            is_exc, _ = check_asset_target_mapping(asset, excluded_targets)
            if is_exc:
                is_excluded = True

        # Check authorized target mapping
        is_mapped, matched_target = check_asset_target_mapping(asset, targets) if (asset and targets) else (False, None)

        if is_excluded:
            finding["scope_validation"] = "OUT_OF_SCOPE"
            finding["validation_status"] = "unverified"
            finding["confidence"] = "unverified"
            missing_evidence.append(
                f"EXCLUDED TARGET VIOLATION: Finding '{finding.get('title')}' targets excluded asset '{asset}'."
            )
        elif not is_mapped:
            finding["scope_validation"] = "OUT_OF_SCOPE"
            finding["validation_status"] = "unverified"
            finding["confidence"] = "unverified"
            missing_evidence.append(
                f"OUT-OF-SCOPE ASSET: Finding '{finding.get('title')}' asset '{asset}' does not map to approved targets."
            )
        else:
            finding["scope_validation"] = "AUTHORIZED"
            finding["matched_target"] = matched_target

            # Confidence rules for in-scope findings
            if not evidence or evidence.strip() == "":
                finding["confidence"] = "unverified"
                finding["validation_status"] = "unverified"
                missing_evidence.append(f"No evidence provided for: {finding.get('title')}")
            elif "synthetic" in source_type.lower() or "synthetic" in evidence.lower() or execution_mode == "demo":
                finding["confidence"] = "suspected"
                finding["validation_status"] = "suspected"
                missing_evidence.append(f"Synthetic evidence only for: {finding.get('title')}")
            elif ("confirmed" in evidence.lower() or "verified" in evidence.lower()) and source_type not in ("synthetic", "llm_generated", "prompt"):
                # Real verification evidence on live systems
                finding["confidence"] = "confirmed"
                finding["validation_status"] = "confirmed"
            else:
                # LLM output or unverified tool output
                finding["confidence"] = "suspected"
                finding["validation_status"] = "suspected"

        validated.append(finding)

    # ── Step 3: LLM-assisted contradiction detection (if available) ──
    gemini_used = False
    gemini_model = None

    if execution_mode != "demo" and len(validated) > 1:
        try:
            provider = get_llm_provider()
            prompt = (
                f"Review these security findings for contradictions or inconsistencies:\n\n"
                f"{json.dumps([{'title': f.get('title'), 'description': f.get('description'), 'severity': f.get('severity')} for f in validated], indent=2)}\n\n"
                f"List any contradictions between findings. Respond with JSON: "
                f'{{"contradictions": ["list of contradictions"]}}'
            )
            raw = await provider.generate(prompt)
            try:
                parsed = json.loads(raw) if raw.startswith("{") else json.loads(
                    raw.split("```json")[-1].split("```")[0] if "```json" in raw else raw
                )
                contradictions = parsed.get("contradictions", [])
                if getattr(provider, "last_used_model", None):
                    gemini_used = True
                    gemini_model = provider.last_used_model
            except json.JSONDecodeError:
                pass
        except GeminiProviderError:
            logger.info("LLM unavailable for contradiction detection — skipping")

    # In demo mode, add standard missing evidence notes
    if execution_mode == "demo":
        missing_evidence.extend([
            "Live TLS scan results needed to confirm TLS findings",
            "Actual HTTP response headers needed for header analysis",
            "Real dependency manifest needed for dependency audit",
            "Network scan needed to confirm port exposure findings",
        ])

    logger.info(
        "Agent 4 (Validation) completed: %d validated, %d duplicates, %d missing evidence items (Gemini: %s)",
        len(validated), duplicates, len(missing_evidence), gemini_used,
    )

    res = {
        "validated_findings": validated,
        "duplicates_found": duplicates,
        "contradictions": contradictions,
        "missing_evidence": missing_evidence,
        "current_agent": "validation",
    }
    if gemini_used:
        res["gemini_used"] = True
        res["gemini_model"] = gemini_model
    return res
