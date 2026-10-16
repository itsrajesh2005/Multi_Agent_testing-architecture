"""
Agent 6 — Report Generation Agent

Generates professional executive summary, JSON report, and HTML report.
Separates confirmed from suspected findings. Escapes untrusted content.
Never claims verification without supporting evidence.
"""

from __future__ import annotations

import html
import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List

from app.agents.state import AssessmentState
from app.services.gemini_provider import get_llm_provider, GeminiProviderError

logger = logging.getLogger("sentinel_ai.agents.report")


async def report_agent(state: AssessmentState) -> Dict[str, Any]:
    """
    Report Generation Agent node for LangGraph.

    - Generates executive summary
    - Creates JSON and HTML reports
    - Separates confirmed from suspected findings
    - Escapes all untrusted content in HTML
    """
    logger.info("Agent 6 (Report) starting for assessment %s", state.get("assessment_id"))

    assessment_id = state.get("assessment_id", "unknown")
    assessment_name = state.get("assessment_name", "Unnamed Assessment")
    execution_mode = state.get("execution_mode", "demo")
    targets = state.get("targets", [])
    findings = state.get("risk_assessed_findings", [])
    plan_limitations = state.get("plan_limitations", [])
    missing_evidence = state.get("missing_evidence", [])
    overall_risk = state.get("overall_risk", "UNKNOWN")
    remediation_priorities = state.get("remediation_priorities", [])

    # ── Generate executive summary ──
    executive_summary, exec_gemini_used, exec_model = await _generate_executive_summary(
        findings, overall_risk, execution_mode, assessment_name
    )

    gemini_used = bool(state.get("gemini_used", False) or exec_gemini_used)
    gemini_model = state.get("gemini_model") or exec_model

    # ── Methodology ──
    methodology = _build_methodology(execution_mode)

    # ── Limitations ──
    all_limitations = list(set(plan_limitations + missing_evidence))
    if execution_mode == "demo":
        all_limitations.insert(0, "DEMO MODE: All findings are synthetic and for demonstration purposes only.")
    limitations_text = "\n".join(f"• {l}" for l in all_limitations)

    # ── Severity summary ──
    severity_summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}
    for f in findings:
        sev = f.get("severity", "informational").lower()
        if sev in severity_summary:
            severity_summary[sev] += 1

    now = datetime.now(timezone.utc)

    # ── Build report findings ──
    report_findings = []
    for i, f in enumerate(findings):
        affected_asset = f.get("affected_asset")
        port_val = f.get("affected_port")
        if not port_val and affected_asset and ":" in str(affected_asset):
            port_val = str(affected_asset).split(":", 1)[1]

        sev_val = str(f.get("severity", "informational")).lower()
        risk_val = str(f.get("risk_rating") or sev_val).upper()

        report_findings.append({
            "finding_id": f"FIND-{i + 1:03d}",
            "title": f.get("title", "Untitled"),
            "description": f.get("description", ""),
            "affected_asset": affected_asset,
            "affected_port": port_val,
            "severity": sev_val,
            "risk_rating": risk_val,
            "confidence": f.get("confidence", "unverified"),
            "validation_status": f.get("validation_status", "unverified"),
            "scope_validation": f.get("scope_validation") or "AUTHORIZED",
            "evidence": f.get("evidence"),
            "cwe_id": f.get("cwe_id"),
            "remediation": f.get("remediation"),
            "references": f.get("references", []),
            "source_type": f.get("source_type", "synthetic"),
            "originating_agent": f.get("originating_agent") or "Vulnerability Analysis Agent",
            "detected_at": f.get("detected_at") or now.isoformat(),
        })

    # ── JSON report ──
    report_json = {
        "assessment_id": assessment_id,
        "assessment_name": assessment_name,
        "assessment_mode": execution_mode,
        "scope": targets,
        "authorization_status": "confirmed",
        "started_at": state.get("started_at", now.isoformat()),
        "completed_at": now.isoformat(),
        "overall_status": "completed",
        "overall_risk": overall_risk,
        "gemini_used": gemini_used,
        "gemini_model": gemini_model,
        "executive_summary": executive_summary,
        "methodology": methodology,
        "findings": report_findings,
        "severity_summary": severity_summary,
        "limitations": limitations_text,
        "remediation_priorities": remediation_priorities,
        "generated_at": now.isoformat(),
    }

    # ── HTML report ──
    report_html = _generate_html_report(report_json)

    logger.info("Agent 6 (Report) completed: %d findings in report (Gemini: %s)", len(report_findings), gemini_used)

    return {
        "executive_summary": executive_summary,
        "methodology": methodology,
        "report_limitations": limitations_text,
        "report_json": report_json,
        "report_html": report_html,
        "gemini_used": gemini_used,
        "gemini_model": gemini_model,
        "current_agent": "report",
        "workflow_status": "completed",
    }


async def _generate_executive_summary(
    findings: List[Dict], overall_risk: str, mode: str, name: str
) -> tuple[str, bool, Optional[str]]:
    """Generate executive summary — LLM-assisted or deterministic."""
    gemini_used = False
    gemini_model = None
    # Try LLM first
    if mode != "demo":
        try:
            provider = get_llm_provider()
            prompt = (
                f"Write a professional executive summary for a security assessment report:\n"
                f"Assessment: {name}\n"
                f"Overall Risk: {overall_risk}\n"
                f"Total Findings: {len(findings)}\n"
                f"Findings: {json.dumps([{'title': f.get('title'), 'severity': f.get('severity')} for f in findings])}\n\n"
                f"Keep it concise (2-3 paragraphs). Be professional and factual."
            )
            raw = await provider.generate(prompt)
            if getattr(provider, "last_used_model", None):
                gemini_used = True
                gemini_model = provider.last_used_model
            return raw, gemini_used, gemini_model
        except GeminiProviderError:
            pass  # fall through to deterministic

    # Deterministic summary
    severity_counts = {}
    for f in findings:
        sev = f.get("severity", "informational")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    mode_label = "DEMO MODE (synthetic evidence)" if mode == "demo" else "LLM-assisted analysis"

    summary_parts = [
        f"[{mode_label.upper()}] Security Assessment Report — {name}",
        "",
        f"This security assessment identified {len(findings)} potential findings with an "
        f"overall risk rating of {overall_risk}.",
    ]

    if severity_counts:
        breakdown = ", ".join(f"{count} {sev}" for sev, count in sorted(
            severity_counts.items(),
            key=lambda x: ["critical", "high", "medium", "low", "informational"].index(x[0])
            if x[0] in ["critical", "high", "medium", "low", "informational"] else 5
        ))
        summary_parts.append(f"Severity breakdown: {breakdown}.")

    if mode == "demo":
        summary_parts.append("")
        summary_parts.append(
            "IMPORTANT: This assessment was conducted in demonstration mode using synthetic "
            "evidence. All findings are hypothetical and should be validated through actual "
            "security testing before taking remediation action."
        )

    summary_parts.append("")
    summary_parts.append(
        "Immediate attention is recommended for critical and high-severity findings. "
        "A detailed remediation plan with prioritized actions is provided in the findings section."
    )

    return "\n".join(summary_parts), False, None


def _build_methodology(mode: str) -> str:
    """Build methodology description."""
    if mode == "demo":
        return (
            "This assessment was conducted in DEMO MODE using the following methodology:\n"
            "1. Scope Validation — Verified assessment scope against authorized targets\n"
            "2. Synthetic Reconnaissance — Analyzed predefined synthetic asset inventory\n"
            "3. Vulnerability Analysis — Applied synthetic findings based on common security weaknesses\n"
            "4. Evidence Validation — Checked finding consistency and detected duplicates\n"
            "5. Risk Assessment — Applied deterministic severity rules based on finding characteristics\n"
            "6. Report Generation — Compiled findings into structured report format\n\n"
            "NOTE: No live scanning, network probes, or external API calls were performed. "
            "All evidence is synthetic and for demonstration purposes only."
        )
    return (
        "This assessment was conducted using the following methodology:\n"
        "1. Scope Validation — Verified assessment scope against authorized targets\n"
        "2. Reconnaissance Analysis — Analyzed supplied asset metadata and configurations\n"
        "3. Vulnerability Analysis — Identified potential weaknesses using evidence analysis\n"
        "4. Evidence Validation — Verified findings against available evidence\n"
        "5. Risk Assessment — Applied severity rules based on impact and exposure\n"
        "6. Report Generation — Compiled findings with remediation recommendations"
    )


def check_asset_target_mapping(asset: Any, targets: List[str]) -> tuple[bool, str | None]:
    """
    Verify whether a finding's affected asset maps to an authorized target in the assessment scope.
    Returns (is_mapped: bool, matched_target: str | None).
    """
    if not asset or not targets:
        return False, None

    asset_str = str(asset).strip().lower()
    if asset_str in ("", "n/a", "none", "unknown", "null"):
        return False, None

    # Strip scheme if present (e.g. http://, https://)
    if "://" in asset_str:
        asset_str = asset_str.split("://", 1)[1]
    # Strip path if present
    asset_str = asset_str.split("/", 1)[0]
    asset_host = asset_str.split(":", 1)[0]
    asset_port = asset_str.split(":", 1)[1] if ":" in asset_str else None

    for target in targets:
        t_str = str(target).strip().lower()
        if "://" in t_str:
            t_str = t_str.split("://", 1)[1]
        t_str = t_str.split("/", 1)[0]
        t_host = t_str.split(":", 1)[0]
        t_port = t_str.split(":", 1)[1] if ":" in t_str else None

        # 1. Exact string match
        if asset_str == t_str:
            return True, str(target)

        # 2. Host match without port (when ports are compatible)
        if asset_host == t_host:
            if asset_port and t_port and asset_port != t_port:
                continue
            return True, str(target)

        # 3. Subdomain match (e.g. "api.lab.local" matches "lab.local"), only for domain names
        is_ip = t_host.replace(".", "").isdigit()
        if not is_ip and asset_host.endswith("." + t_host):
            return True, str(target)

    return False, None


def _calculate_overall_risk(report_data: Dict[str, Any]) -> str:
    """Determine overall risk rating from report data or findings."""
    raw_risk = str(report_data.get("overall_risk") or "").strip().upper()
    if raw_risk in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"):
        return raw_risk

    findings = report_data.get("findings", [])
    severities = [str(f.get("severity", "informational")).lower() for f in findings]
    if "critical" in severities:
        return "CRITICAL"
    if "high" in severities:
        return "HIGH"
    if "medium" in severities:
        return "MEDIUM"
    if "low" in severities:
        return "LOW"
    return "INFORMATIONAL"


def _detect_gemini_usage(report_data: Dict[str, Any]) -> tuple[bool, str, str]:
    """
    Determine whether Gemini was actually used based on recorded execution metadata.
    Returns (gemini_used: bool, badge_html: str, description_text: str).
    """
    mode = str(report_data.get("assessment_mode", "")).lower()

    if report_data.get("gemini_used") is True:
        model = report_data.get("gemini_model") or "gemini-3-flash-preview"
        return (
            True,
            f'<span class="badge badge-gemini-active">GEMINI ACTIVE ({model})</span>',
            f"Gemini LLM ({model}) was actively used for automated reasoning during this assessment.",
        )
    elif report_data.get("gemini_used") is False and "gemini_used" in report_data:
        return (
            False,
            '<span class="badge badge-gemini-inactive">GEMINI NOT USED (DETERMINISTIC FALLBACK)</span>',
            "Deterministic fallback engine executed; Gemini was not invoked or was unavailable.",
        )

    if mode == "demo":
        return (
            False,
            '<span class="badge badge-gemini-inactive">GEMINI NOT USED (DEMO MODE)</span>',
            "Demo mode: Predefined synthetic security simulation executed without external LLM calls.",
        )

    return (
        False,
        '<span class="badge badge-gemini-inactive">GEMINI NOT USED (FALLBACK ENGINE)</span>',
        "Rule-based deterministic fallback engine executed.",
    )


def _build_complete_remediation_priorities(report_data: Dict[str, Any]) -> List[str]:
    """
    Ensure all remediation priorities contain full, unabridged remediation text
    without character truncation.
    """
    findings = report_data.get("findings", [])
    findings_map = {f.get("title", ""): f.get("remediation", "") for f in findings if f.get("title")}

    raw_priorities = report_data.get("remediation_priorities", [])
    if not raw_priorities:
        result = []
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
        sorted_findings = sorted(
            [f for f in findings if f.get("remediation")],
            key=lambda f: severity_order.get(str(f.get("severity", "informational")).lower(), 5),
        )
        for i, f in enumerate(sorted_findings):
            sev = str(f.get("severity", "informational")).upper()
            result.append(f"Priority {i + 1} [{sev}]: {f.get('title')} — {f.get('remediation')}")
        return result

    complete_priorities = []
    for item in raw_priorities:
        prio_str = str(item)
        # Restore full text if priority was previously truncated by [:200]
        for title, rem in findings_map.items():
            if title and title in prio_str and rem:
                if len(rem) > 180 and rem[:150] in prio_str and not prio_str.endswith(rem[-20:]):
                    prefix = prio_str.split("—")[0].strip() if "—" in prio_str else (prio_str.split("-")[0].strip() if "-" in prio_str else "")
                    if prefix:
                        prio_str = f"{prefix} — {rem}"
                    break
        complete_priorities.append(prio_str)

    return complete_priorities


def _generate_html_report(report_data: Dict[str, Any]) -> str:
    """Generate a professional HTML report with escaped untrusted content."""

    def esc(text: Any) -> str:
        """Escape untrusted content for safe HTML rendering."""
        if text is None:
            return ""
        return html.escape(str(text))

    mode = str(report_data.get("assessment_mode", "demo")).lower()
    targets = [str(t) for t in report_data.get("scope", []) if t]
    findings = report_data.get("findings", [])

    # 1. Separate execution status from overall risk rating
    execution_status = esc(report_data.get("execution_status") or report_data.get("overall_status") or "completed").upper()
    overall_risk = esc(_calculate_overall_risk(report_data)).upper()

    status_badge_class = f"badge-status-{execution_status.lower()}"
    risk_badge_class = f"severity-{overall_risk.lower()}"

    # 2. Gemini usage metadata
    gemini_used, gemini_badge, gemini_desc = _detect_gemini_usage(report_data)

    # 3. Scope verification and target mapping
    mapped_count = 0
    unmapped_assets_set = set()

    for f in findings:
        is_mapped, _ = check_asset_target_mapping(f.get("affected_asset"), targets)
        if is_mapped:
            mapped_count += 1
        else:
            asset_label = str(f.get("affected_asset") or "Unspecified Asset")
            unmapped_assets_set.add(asset_label)

    unmapped_count = len(findings) - mapped_count
    has_unmapped = unmapped_count > 0

    # Check if assessment contains synthetic findings
    has_synthetic_findings = any(
        str(f.get("source_type", "")).lower() == "synthetic" or mode == "demo"
        for f in findings
    )

    # 4. Render findings cards with provenance, confidence, verification status, and limitations
    findings_html = ""
    for f in findings:
        severity = esc(f.get("severity", "informational")).lower()
        severity_class = f"severity-{severity}"
        source_type = str(f.get("source_type", "synthetic")).lower()
        is_synthetic = (source_type == "synthetic" or mode == "demo")

        confidence_val = str(f.get("confidence", "unverified")).lower()
        validation_status_val = str(f.get("validation_status", "unverified")).lower()
        affected_asset = f.get("affected_asset")

        # Verify asset against authorized targets
        is_asset_mapped, matched_target = check_asset_target_mapping(affected_asset, targets)

        # Labels & Badges
        if is_synthetic:
            synthetic_badge = '<span class="badge badge-synthetic">SYNTHETIC EVIDENCE (DEMO)</span>'
            verification_badge = '<span class="badge badge-unverified">NOT LIVE VERIFIED</span>'
            verification_display = "Suspected / Unverified — Synthetic test scenario (not verified on live target)"
            confidence_display = "Suspected (Synthetic Simulation)"
            provenance_display = "Synthetic Demonstration Finding (Predefined Security Weakness Scenario)"
        else:
            synthetic_badge = '<span class="badge badge-live">LIVE EVIDENCE</span>'
            verification_badge = f'<span class="badge badge-verification-{validation_status_val}">{esc(validation_status_val.upper())}</span>'
            verification_display = f"{esc(validation_status_val.capitalize())} via evidence analysis"
            confidence_display = esc(confidence_val.capitalize())
            provenance_display = esc(f.get("source_type", "Automated Security Analysis"))

        if is_asset_mapped:
            asset_scope_badge = f'<span class="badge badge-mapped">✓ IN SCOPE ({esc(matched_target)})</span>'
            asset_display = f'<span class="asset-mapped">{esc(affected_asset or "N/A")}</span> <span class="badge badge-mapped-sm">✓ Mapped to {esc(matched_target)}</span>'
        else:
            asset_scope_badge = '<span class="badge badge-unmapped">⚠️ UNMAPPED ASSET</span>'
            asset_display = f'<span class="asset-unmapped">{esc(affected_asset or "N/A")}</span> <span class="badge badge-unmapped-sm">⚠️ Unmapped — Outside Authorized Scope Targets</span>'

        # Build specific limitations for this finding
        f_limitations = []
        if is_synthetic:
            f_limitations.append("Synthetic evidence generated for simulation; this finding has not been validated on a live target and is not a confirmed vulnerability.")
        if not is_asset_mapped:
            f_limitations.append(f"Affected asset '{esc(affected_asset or 'N/A')}' does not map to any authorized target in assessment scope ({esc(', '.join(targets))}).")
        if confidence_val in ("suspected", "unverified"):
            f_limitations.append("Theoretical finding based on configuration checks. Exploitability has not been proven.")

        limitations_html = ""
        if f_limitations:
            limitations_html = '<div class="finding-field"><strong>Finding Limitations:</strong><ul class="finding-limitations">' + "".join(f"<li>{esc(lim)}</li>" for lim in f_limitations) + "</ul></div>"

        # Complete, untruncated remediation
        remediation_text = esc(f.get("remediation", "No remediation provided."))

        findings_html += f"""
        <div class="finding-card {severity_class}">
            <div class="finding-header">
                <span class="finding-id">{esc(f.get('finding_id', 'FIND-???'))}</span>
                <span class="severity-badge {severity_class}">{severity.upper()}</span>
                {synthetic_badge}
                {asset_scope_badge}
                {verification_badge}
            </div>
            <h3>{esc(f.get('title', 'Untitled Finding'))}</h3>
            
            <div class="finding-details-grid">
                <div class="finding-field">
                    <strong>Affected Asset:</strong> {asset_display}
                </div>
                <div class="finding-field">
                    <strong>Evidence Provenance:</strong> {esc(provenance_display)}
                </div>
                <div class="finding-field">
                    <strong>Confidence Level:</strong> {esc(confidence_display)}
                </div>
                <div class="finding-field">
                    <strong>Verification Status:</strong> {esc(verification_display)}
                </div>
                {f'<div class="finding-field"><strong>CWE Identifier:</strong> {esc(f.get("cwe_id"))}</div>' if f.get('cwe_id') else ''}
            </div>

            <div class="finding-field" style="margin-top: 0.75rem;">
                <strong>Description:</strong>
                <p class="description-text">{esc(f.get('description', ''))}</p>
            </div>

            <div class="finding-field" style="margin-top: 0.75rem;">
                <strong>Evidence:</strong>
                <pre class="evidence-box">{esc(f.get('evidence', 'No evidence provided.'))}</pre>
            </div>

            {limitations_html}

            <div class="remediation">
                <strong>Remediation & Recommendation:</strong>
                <p class="remediation-text">{remediation_text}</p>
            </div>
        </div>
        """

    sev_summary = report_data.get("severity_summary", {})

    # 5. Build complete, unabridged remediation priorities
    complete_priorities = _build_complete_remediation_priorities(report_data)
    priorities_html = ""
    for prio_item in complete_priorities:
        priorities_html += f"""
        <div class="priority-card">
            <p class="priority-text">{esc(prio_item)}</p>
        </div>
        """

    mode_badge = (
        '<span class="badge badge-demo">DEMO MODE</span>'
        if mode == "demo"
        else '<span class="badge badge-live">LLM-ASSISTED</span>'
    )

    # Scope verification banner in Scope section
    scope_targets_display = ", ".join(esc(t) for t in targets) if targets else "None specified"
    if has_unmapped:
        scope_verification_html = f"""
        <div class="scope-alert-box">
            <strong>⚠️ Target Scope Alert:</strong> {unmapped_count} of {len(findings)} finding(s) reference assets not present in the authorized target scope ({esc(', '.join(sorted(unmapped_assets_set)))}).
            These findings have been flagged as unmapped and should not be assumed to belong to the target environment.
        </div>
        """
    else:
        scope_verification_html = f"""
        <div class="scope-success-box">
            <strong>✓ Scope Verification:</strong> All {len(findings)} finding(s) map directly to authorized targets.
        </div>
        """

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SentinelAI Security Assessment Report — {esc(report_data.get('assessment_name'))}</title>
    <style>
        :root {{
            --bg-primary: #0f172a;
            --bg-secondary: #1e293b;
            --bg-card: #1e293b;
            --text-primary: #f1f5f9;
            --text-secondary: #94a3b8;
            --accent: #3b82f6;
            --critical: #ef4444;
            --high: #f97316;
            --medium: #eab308;
            --low: #22c55e;
            --info: #6366f1;
            --border: #334155;
        }}
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
            padding: 2rem;
        }}
        .container {{ max-width: 1100px; margin: 0 auto; }}
        .header {{
            padding: 2rem;
            background: linear-gradient(135deg, var(--bg-secondary), #0f172a);
            border-radius: 12px;
            border: 1px solid var(--border);
            margin-bottom: 2rem;
        }}
        .header-title-row {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 1rem;
            margin-bottom: 0.5rem;
        }}
        .header h1 {{ font-size: 1.8rem; }}
        .header p {{ color: var(--text-secondary); }}
        .report-meta-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 1rem;
            margin-top: 1.5rem;
            padding-top: 1.5rem;
            border-top: 1px solid var(--border);
        }}
        .meta-box {{
            background: rgba(15, 23, 42, 0.6);
            padding: 0.75rem 1rem;
            border-radius: 8px;
            border: 1px solid var(--border);
        }}
        .meta-box .meta-title {{
            font-size: 0.75rem;
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-bottom: 0.35rem;
            font-weight: 600;
        }}
        .meta-box .meta-val {{
            display: flex;
            align-items: center;
            gap: 0.5rem;
            font-size: 0.95rem;
            font-weight: 600;
        }}
        .badge {{
            display: inline-block;
            padding: 0.25rem 0.75rem;
            border-radius: 999px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
        }}
        .badge-demo {{ background: #f59e0b22; color: #f59e0b; border: 1px solid #f59e0b44; }}
        .badge-live {{ background: #22c55e22; color: #22c55e; border: 1px solid #22c55e44; }}
        .badge-status-completed {{ background: #22c55e22; color: #4ade80; border: 1px solid #22c55e55; }}
        .badge-status-running {{ background: #0284c722; color: #38bdf8; border: 1px solid #0284c755; }}
        .badge-status-failed {{ background: #ef444422; color: #f87171; border: 1px solid #ef444455; }}
        .badge-synthetic {{ background: #d9770622; color: #fbbf24; border: 1px solid #d9770655; }}
        .badge-unverified {{ background: #64748b22; color: #cbd5e1; border: 1px solid #64748b55; }}
        .badge-unmapped {{ background: #dc262622; color: #fca5a5; border: 1px solid #dc262655; }}
        .badge-unmapped-sm {{ background: #dc262622; color: #fca5a5; border: 1px solid #dc262655; font-size: 0.7rem; padding: 0.1rem 0.4rem; border-radius: 4px; }}
        .badge-mapped {{ background: #16a34a22; color: #4ade80; border: 1px solid #16a34a55; }}
        .badge-mapped-sm {{ background: #16a34a22; color: #4ade80; border: 1px solid #16a34a55; font-size: 0.7rem; padding: 0.1rem 0.4rem; border-radius: 4px; }}
        .badge-gemini-active {{ background: #8b5cf622; color: #a78bfa; border: 1px solid #8b5cf655; }}
        .badge-gemini-inactive {{ background: #64748b22; color: #94a3b8; border: 1px solid #64748b55; }}
        .section {{
            background: var(--bg-card);
            border-radius: 12px;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
            border: 1px solid var(--border);
        }}
        .section h2 {{
            font-size: 1.2rem;
            margin-bottom: 1rem;
            padding-bottom: 0.5rem;
            border-bottom: 1px solid var(--border);
        }}
        .severity-grid {{
            display: grid;
            grid-template-columns: repeat(5, 1fr);
            gap: 1rem;
            margin-bottom: 1rem;
        }}
        .severity-box {{
            text-align: center;
            padding: 1rem;
            border-radius: 8px;
            border: 1px solid var(--border);
        }}
        .severity-box.critical {{ border-color: var(--critical); background: #ef444415; }}
        .severity-box.high {{ border-color: var(--high); background: #f9731615; }}
        .severity-box.medium {{ border-color: var(--medium); background: #eab30815; }}
        .severity-box.low {{ border-color: var(--low); background: #22c55e15; }}
        .severity-box.info {{ border-color: var(--info); background: #6366f115; }}
        .severity-box .count {{ font-size: 2rem; font-weight: 700; }}
        .severity-box .label {{ font-size: 0.75rem; color: var(--text-secondary); text-transform: uppercase; }}
        .finding-card {{
            background: var(--bg-primary);
            border-radius: 8px;
            padding: 1.25rem;
            margin-bottom: 1.25rem;
            border-left: 4px solid var(--border);
        }}
        .finding-card.severity-critical {{ border-left-color: var(--critical); }}
        .finding-card.severity-high {{ border-left-color: var(--high); }}
        .finding-card.severity-medium {{ border-left-color: var(--medium); }}
        .finding-card.severity-low {{ border-left-color: var(--low); }}
        .finding-card.severity-informational {{ border-left-color: var(--info); }}
        .finding-header {{
            display: flex;
            flex-wrap: wrap;
            gap: 0.5rem;
            align-items: center;
            margin-bottom: 0.75rem;
        }}
        .finding-id {{ font-family: monospace; color: var(--text-secondary); font-size: 0.85rem; font-weight: 600; }}
        .severity-badge {{
            padding: 0.2rem 0.6rem;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 700;
        }}
        .severity-badge.severity-critical {{ background: var(--critical); color: white; }}
        .severity-badge.severity-high {{ background: var(--high); color: white; }}
        .severity-badge.severity-medium {{ background: var(--medium); color: #1e293b; }}
        .severity-badge.severity-low {{ background: var(--low); color: #1e293b; }}
        .severity-badge.severity-informational {{ background: var(--info); color: white; }}
        .finding-details-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 0.5rem 1rem;
            margin-top: 0.5rem;
            font-size: 0.9rem;
            color: var(--text-secondary);
        }}
        .finding-field strong {{ color: #cbd5e1; }}
        .finding-card h3 {{ font-size: 1.1rem; margin-bottom: 0.5rem; color: #f8fafc; }}
        .description-text {{ color: #d1d5db; font-size: 0.9rem; margin-top: 0.25rem; }}
        .evidence-box {{
            background: rgba(15, 23, 42, 0.8);
            border: 1px solid var(--border);
            padding: 0.75rem;
            border-radius: 6px;
            margin-top: 0.35rem;
            white-space: pre-wrap;
            word-break: break-word;
            font-family: monospace;
            font-size: 0.85rem;
            color: #93c5fd;
        }}
        .finding-limitations {{
            list-style: disc;
            margin-left: 1.5rem;
            color: #fca5a5;
            font-size: 0.85rem;
            margin-top: 0.25rem;
        }}
        .remediation {{
            background: var(--bg-secondary);
            padding: 0.85rem 1rem;
            border-radius: 6px;
            margin-top: 0.75rem;
            border-left: 3px solid #38bdf8;
        }}
        .remediation-text {{
            color: #e2e8f0;
            font-size: 0.9rem;
            margin-top: 0.25rem;
            white-space: pre-wrap;
            word-break: break-word;
            line-height: 1.6;
        }}
        .asset-unmapped {{ color: #f87171; font-weight: 600; font-family: monospace; }}
        .asset-mapped {{ color: #4ade80; font-weight: 500; font-family: monospace; }}
        .demo-warning {{
            background: #f59e0b15;
            border: 1px solid #f59e0b44;
            color: #fbbf24;
            padding: 1rem;
            border-radius: 8px;
            text-align: center;
            margin-bottom: 1.5rem;
            font-weight: 600;
            font-size: 0.95rem;
            line-height: 1.5;
        }}
        .scope-alert-box {{
            background: #ef444415;
            border: 1px solid #ef444444;
            color: #fca5a5;
            padding: 0.85rem 1rem;
            border-radius: 6px;
            margin-top: 0.75rem;
            font-size: 0.9rem;
        }}
        .scope-success-box {{
            background: #22c55e15;
            border: 1px solid #22c55e44;
            color: #86efac;
            padding: 0.85rem 1rem;
            border-radius: 6px;
            margin-top: 0.75rem;
            font-size: 0.9rem;
        }}
        .priority-card {{
            background: var(--bg-primary);
            border-radius: 6px;
            padding: 0.85rem 1rem;
            margin-bottom: 0.5rem;
            border-left: 3px solid #38bdf8;
        }}
        .priority-text {{
            color: #e2e8f0;
            font-size: 0.9rem;
            white-space: pre-wrap;
            word-break: break-word;
            line-height: 1.6;
        }}
        pre {{
            white-space: pre-wrap;
            word-wrap: break-word;
            font-size: 0.85rem;
            color: var(--text-secondary);
        }}
        .footer {{
            text-align: center;
            padding: 1.5rem;
            color: var(--text-secondary);
            font-size: 0.8rem;
        }}
        @media print {{
            body {{ background: white; color: #1e293b; padding: 1rem; }}
            .finding-card {{ break-inside: avoid; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="header-title-row">
                <h1>🛡️ SentinelAI Security Assessment Report</h1>
                <div>{mode_badge}</div>
            </div>
            <p>Assessment: <strong>{esc(report_data.get('assessment_name'))}</strong> (ID: {esc(report_data.get('assessment_id'))})</p>
            
            <div class="report-meta-grid">
                <div class="meta-box">
                    <div class="meta-title">Execution Status</div>
                    <div class="meta-val"><span class="badge {status_badge_class}">{execution_status}</span></div>
                </div>
                <div class="meta-box">
                    <div class="meta-title">Overall Risk Rating</div>
                    <div class="meta-val"><span class="severity-badge {risk_badge_class}">{overall_risk}</span></div>
                </div>
                <div class="meta-box">
                    <div class="meta-title">AI / Gemini Engine</div>
                    <div class="meta-val">{gemini_badge}</div>
                </div>
                <div class="meta-box">
                    <div class="meta-title">Generated At</div>
                    <div class="meta-val" style="font-size: 0.85rem; font-weight: normal; color: var(--text-secondary);">{esc(report_data.get('generated_at', ''))}</div>
                </div>
            </div>
        </div>

        {'<div class="demo-warning">⚠️ SYNTHETIC EVIDENCE NOTICE — Findings labeled as SYNTHETIC were generated for simulation/demonstration purposes. They have NOT been verified against live systems and must NOT be treated as confirmed vulnerabilities.</div>' if has_synthetic_findings else ''}

        <div class="section">
            <h2>📋 Executive Summary</h2>
            <pre>{esc(report_data.get('executive_summary', ''))}</pre>
        </div>

        <div class="section">
            <h2>📊 Severity Summary</h2>
            <div class="severity-grid">
                <div class="severity-box critical">
                    <div class="count" style="color: var(--critical);">{sev_summary.get('critical', 0)}</div>
                    <div class="label">Critical</div>
                </div>
                <div class="severity-box high">
                    <div class="count" style="color: var(--high);">{sev_summary.get('high', 0)}</div>
                    <div class="label">High</div>
                </div>
                <div class="severity-box medium">
                    <div class="count" style="color: var(--medium);">{sev_summary.get('medium', 0)}</div>
                    <div class="label">Medium</div>
                </div>
                <div class="severity-box low">
                    <div class="count" style="color: var(--low);">{sev_summary.get('low', 0)}</div>
                    <div class="label">Low</div>
                </div>
                <div class="severity-box info">
                    <div class="count" style="color: var(--info);">{sev_summary.get('informational', 0)}</div>
                    <div class="label">Info</div>
                </div>
            </div>
        </div>

        <div class="section">
            <h2>🎯 Scope & Target Verification</h2>
            <p><strong>Authorized Scope Targets:</strong> {scope_targets_display}</p>
            <p><strong>Execution Mode:</strong> {esc(mode)}</p>
            <p><strong>AI Engine Status:</strong> {gemini_desc}</p>
            <p><strong>Authorization Status:</strong> {esc(report_data.get('authorization_status', 'confirmed'))}</p>
            {scope_verification_html}
        </div>

        <div class="section">
            <h2>🔬 Methodology</h2>
            <pre>{esc(report_data.get('methodology', ''))}</pre>
        </div>

        <div class="section">
            <h2>🔍 Findings ({len(findings)})</h2>
            {findings_html if findings_html else '<p style="color: var(--text-secondary);">No findings identified in this assessment.</p>'}
        </div>

        <div class="section">
            <h2>⚠️ Assessment Limitations</h2>
            <pre>{esc(report_data.get('limitations', 'None documented'))}</pre>
        </div>

        <div class="section">
            <h2>🔧 Remediation Priorities</h2>
            {priorities_html if priorities_html else '<p style="color: var(--text-secondary);">No remediation priorities established.</p>'}
        </div>

        <div class="footer">
            <p>Generated by SentinelAI — Multi-Agent Penetration Testing Platform</p>
            <p>This report is confidential and intended for authorized recipients only.</p>
        </div>
    </div>
</body>
</html>"""

