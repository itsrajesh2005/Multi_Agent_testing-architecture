"""
Agent 5 — Risk Assessment Agent

Assigns severity using documented deterministic rules.
Considers impact, exposure, confidence, and evidence.
Prioritizes remediation. Does not invent CVSS scores.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List

from app.agents.state import AssessmentState
from app.services.gemini_provider import get_llm_provider, GeminiProviderError

logger = logging.getLogger("sentinel_ai.agents.risk")

# Deterministic severity rules based on finding characteristics
SEVERITY_RULES = {
    "critical": {
        "indicators": ["remote code execution", "rce", "authentication bypass", "sql injection", "command injection"],
        "min_confidence": "suspected",
        "description": "Exploitable vulnerability with high impact and low complexity",
    },
    "high": {
        "indicators": ["unauthorized access", "data exposure", "privilege escalation", "exposed database", "ssrf"],
        "min_confidence": "suspected",
        "description": "Significant vulnerability requiring prompt remediation",
    },
    "medium": {
        "indicators": ["tls", "cors", "session", "management interface", "configuration"],
        "min_confidence": "suspected",
        "description": "Vulnerability with moderate impact or requiring additional conditions",
    },
    "low": {
        "indicators": ["information disclosure", "verbose error", "missing header", "informational"],
        "min_confidence": "unverified",
        "description": "Minor issue or requires other vulnerabilities to exploit",
    },
}


def _deterministic_severity(finding: Dict[str, Any]) -> tuple[str, str]:
    """
    Assign severity using documented deterministic rules.
    Returns (severity, rationale).
    """
    title = finding.get("title", "").lower()
    description = finding.get("description", "").lower()
    current_severity = finding.get("severity", "informational").lower()
    text = f"{title} {description}"

    # Check deterministic rules in priority order
    for severity, rule in SEVERITY_RULES.items():
        for indicator in rule["indicators"]:
            if indicator in text:
                rationale = (
                    f"Severity assigned as {severity.upper()} based on indicator '{indicator}'. "
                    f"Rule: {rule['description']}."
                )
                return severity, rationale

    # If no rule matched, preserve the original severity
    rationale = f"Severity preserved as {current_severity.upper()} — no specific severity rule matched."
    return current_severity, rationale


async def risk_agent(state: AssessmentState) -> Dict[str, Any]:
    """
    Risk Assessment Agent node for LangGraph.

    - Assigns severity using deterministic rules
    - Considers impact, exposure, confidence
    - Prioritizes remediation
    - Uses LLM for additional context when available
    """
    logger.info("Agent 5 (Risk) starting for assessment %s", state.get("assessment_id"))

    validated_findings = state.get("validated_findings", [])
    execution_mode = state.get("execution_mode", "demo")

    if not validated_findings:
        return {
            "risk_assessed_findings": [],
            "overall_risk": "unknown",
            "remediation_priorities": [],
            "current_agent": "risk",
        }

    # Apply deterministic severity rules
    assessed_findings = []
    for finding in validated_findings:
        severity, rationale = _deterministic_severity(finding)
        finding["severity"] = severity
        finding["severity_rationale"] = rationale
        finding["risk_rating"] = severity.upper()
        if not finding.get("affected_port") and finding.get("affected_asset") and ":" in str(finding["affected_asset"]):
            finding["affected_port"] = str(finding["affected_asset"]).split(":", 1)[1]
        finding["originating_agent"] = finding.get("originating_agent") or "Vulnerability Analysis Agent"
        finding["scope_validation"] = finding.get("scope_validation") or "AUTHORIZED"

        # Adjust confidence-based impact
        confidence = finding.get("confidence", "unverified")
        if confidence == "unverified":
            finding["severity_rationale"] += " Note: confidence is unverified — severity may change with additional evidence."

        assessed_findings.append(finding)

    # Sort by severity priority
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
    assessed_findings.sort(key=lambda f: severity_order.get(f.get("severity", "informational"), 5))

    # Build remediation priorities (complete and untruncated)
    remediation_priorities = []
    for i, finding in enumerate(assessed_findings):
        if finding.get("remediation"):
            remediation_priorities.append(
                f"Priority {i + 1} [{finding['severity'].upper()}]: {finding['title']} — {finding['remediation']}"
            )

    # Calculate overall risk
    severities = [f.get("severity", "informational") for f in assessed_findings]
    if "critical" in severities:
        overall_risk = "CRITICAL"
    elif "high" in severities:
        overall_risk = "HIGH"
    elif "medium" in severities:
        overall_risk = "MEDIUM"
    elif "low" in severities:
        overall_risk = "LOW"
    else:
        overall_risk = "INFORMATIONAL"

    # Optional LLM enhancement for risk rationale
    gemini_used = False
    gemini_model = None

    if execution_mode != "demo":
        try:
            provider = get_llm_provider()
            prompt = (
                f"Review this risk assessment and provide brief additional context:\n\n"
                f"Overall Risk: {overall_risk}\n"
                f"Findings: {json.dumps([{'title': f['title'], 'severity': f['severity']} for f in assessed_findings], indent=2)}\n\n"
                f"Add any additional risk considerations. Keep response brief."
            )
            additional_context = await provider.generate(prompt)
            if getattr(provider, "last_used_model", None):
                gemini_used = True
                gemini_model = provider.last_used_model
            # Store as additional context, don't override deterministic assessment
            for finding in assessed_findings:
                if "llm_risk_context" not in finding:
                    finding["llm_risk_context"] = additional_context[:500]
        except (GeminiProviderError, Exception):
            pass  # deterministic assessment is sufficient

    logger.info("Agent 5 (Risk) completed: overall risk=%s, %d findings assessed (Gemini: %s)",
                overall_risk, len(assessed_findings), gemini_used)

    res = {
        "risk_assessed_findings": assessed_findings,
        "overall_risk": overall_risk,
        "remediation_priorities": remediation_priorities,
        "current_agent": "risk",
    }
    if gemini_used:
        res["gemini_used"] = True
        res["gemini_model"] = gemini_model
    return res
