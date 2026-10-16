"""
Agent 2 — Reconnaissance Analysis Agent

Analyzes supplied asset metadata and synthetic lab information.
Produces structured observations with evidence sources.
Never scans arbitrary public IPs or domains.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List

from app.agents.state import AssessmentState
from app.services.gemini_provider import get_llm_provider, GeminiProviderError

logger = logging.getLogger("sentinel_ai.agents.recon")

# Synthetic asset inventory for demo mode
SYNTHETIC_ASSETS = [
    {
        "asset": "demo.lab.local",
        "type": "web_application",
        "ip": "192.168.1.10",
        "technology_stack": ["Python 3.11", "Flask 2.3", "PostgreSQL 15", "nginx 1.24"],
        "open_ports": [80, 443, 5432],
        "os": "Ubuntu 22.04 LTS",
        "observations": "Web application with database backend. TLS configured but supports legacy versions.",
        "source": "synthetic_inventory",
    },
    {
        "asset": "api.lab.local",
        "type": "api_server",
        "ip": "192.168.1.11",
        "technology_stack": ["Node.js 18", "Express 4.18", "MongoDB 6.0"],
        "open_ports": [443, 8080, 27017],
        "os": "Ubuntu 22.04 LTS",
        "observations": "REST API server. CORS headers present but overly permissive.",
        "source": "synthetic_inventory",
    },
    {
        "asset": "db.lab.local",
        "type": "database_server",
        "ip": "192.168.1.12",
        "technology_stack": ["PostgreSQL 15", "pgAdmin 4"],
        "open_ports": [5432, 8443],
        "os": "Debian 12",
        "observations": "Database server with management interface exposed. No network segmentation observed.",
        "source": "synthetic_inventory",
    },
]


async def recon_agent(state: AssessmentState) -> Dict[str, Any]:
    """
    Reconnaissance Analysis Agent node for LangGraph.

    - Analyzes supplied asset metadata
    - Uses synthetic inventory in demo mode
    - Identifies missing info and config weaknesses
    - Never performs live scanning
    """
    logger.info("Agent 2 (Recon) starting for assessment %s", state.get("assessment_id"))

    targets = state.get("targets", [])
    execution_mode = state.get("execution_mode", "demo")

    # Gather asset data — synthetic in demo mode
    asset_data = _get_asset_data(targets, execution_mode)

    # Use LLM to analyze asset data if available
    observations = asset_data
    missing_info: List[str] = []

    gemini_used = False
    gemini_model = None

    provider = get_llm_provider()
    try:
        prompt = (
            f"Analyze the following asset inventory for security assessment purposes:\n\n"
            f"{json.dumps(asset_data, indent=2)}\n\n"
            f"Identify:\n"
            f"1. Security-relevant observations about each asset\n"
            f"2. Configuration weaknesses visible from the metadata\n"
            f"3. Missing information that would be needed for a thorough assessment\n\n"
            f"Respond with JSON containing 'observations' (list of asset objects) and "
            f"'missing_information' (list of strings)."
        )
        raw = await provider.generate(prompt)
        try:
            parsed = json.loads(raw) if raw.startswith("{") else json.loads(
                raw.split("```json")[-1].split("```")[0] if "```json" in raw else raw
            )
            if "observations" in parsed:
                observations = parsed["observations"]
            if "missing_information" in parsed:
                missing_info = parsed["missing_information"]
            if getattr(provider, "last_used_model", None):
                gemini_used = True
                gemini_model = provider.last_used_model
        except json.JSONDecodeError:
            logger.warning("Could not parse LLM recon response, using raw asset data")
    except GeminiProviderError as e:
        logger.warning("LLM unavailable for recon: %s", e)

    # Add standard missing info items
    if execution_mode == "demo":
        missing_info.extend([
            "Actual network topology (demo mode — synthetic only)",
            "Real TLS certificate details",
            "Live service version detection",
            "Actual firewall rule configuration",
        ])

    logger.info("Agent 2 (Recon) completed: %d observations, %d missing info items (Gemini: %s)",
                len(observations), len(missing_info), gemini_used)

    res = {
        "recon_observations": observations,
        "recon_missing_info": missing_info,
        "current_agent": "recon",
    }
    if gemini_used:
        res["gemini_used"] = True
        res["gemini_model"] = gemini_model
    return res


def _get_asset_data(targets: List[str], mode: str) -> List[Dict[str, Any]]:
    """Get asset data — synthetic for demo, or from supplied metadata."""
    if mode == "demo":
        # Filter synthetic assets to match requested targets
        matched = []
        for asset in SYNTHETIC_ASSETS:
            for target in targets:
                t = target.lower().strip()
                if t in asset["asset"].lower() or t in asset.get("ip", ""):
                    matched.append(asset)
                    break
        # If no specific match, return all synthetic assets
        return matched if matched else SYNTHETIC_ASSETS

    # In LLM-assisted mode, still use supplied metadata (never live scan)
    return [{"asset": t, "type": "unknown", "source": "user_supplied", "observations": "Awaiting metadata"} for t in targets]
