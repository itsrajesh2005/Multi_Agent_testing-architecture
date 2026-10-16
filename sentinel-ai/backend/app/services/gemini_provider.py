"""Gemini LLM provider with deterministic fallback for demo/offline mode."""

from __future__ import annotations

import json
import logging
import time
from typing import Any, Optional, Type

from pydantic import BaseModel

from app.core.config import get_settings

logger = logging.getLogger("sentinel_ai.gemini")


class GeminiProviderError(Exception):
    """Raised when the Gemini API call fails."""
    pass


class GeminiProvider:
    """
    Wraps the Google Gen AI SDK.
    Falls back to deterministic responses when the API key is missing.
    """

    def __init__(self):
        self.settings = get_settings()
        self._client = None
        self._model_name = self.settings.gemini_model
        self._is_available = False
        self._last_used_model: Optional[str] = None
        self._successful_calls: int = 0
        self._init_client()

    def _init_client(self):
        """Initialize the Gemini client if configured."""
        if not self.settings.is_gemini_configured:
            logger.info("Gemini API key not configured — running in demo mode")
            return

        try:
            from google import genai
            self._client = genai.Client(api_key=self.settings.gemini_api_key)
            self._is_available = True
            logger.info("Gemini client initialized with model: %s", self._model_name)
        except ImportError:
            logger.warning("google-genai package not installed — running in demo mode")
        except Exception as e:
            logger.error("Failed to initialize Gemini client: %s", str(e))

    @property
    def is_available(self) -> bool:
        return self._is_available

    @property
    def last_used_model(self) -> Optional[str]:
        return self._last_used_model

    @property
    def successful_calls(self) -> int:
        return self._successful_calls

    async def generate(
        self,
        prompt: str,
        system_instruction: str | None = None,
        response_schema: Type[BaseModel] | None = None,
        max_retries: int = 3,
        timeout: float = 30.0,
    ) -> str:
        """
        Generate text using Gemini or return deterministic fallback.

        Args:
            prompt: The user prompt
            system_instruction: Optional system instruction
            response_schema: Optional Pydantic model for structured output
            max_retries: Number of retries on transient failures
            timeout: Request timeout in seconds

        Returns:
            The generated text response
        """
        if not self._is_available:
            raise GeminiProviderError("Gemini is not available — use demo provider")

        last_error = None
        models_to_try = [self._model_name]
        candidate_models = [
            "gemini-3-flash-preview",
            "gemini-3.1-flash-lite",
            "gemini-flash-latest",
            "gemini-3.8-flash",
            "gemini-2.5-flash",
        ]
        for alt in candidate_models:
            if alt not in models_to_try:
                models_to_try.append(alt)

        for current_model in models_to_try:
            for attempt in range(max_retries):
                try:
                    from google import genai
                    from google.genai import types

                    config = types.GenerateContentConfig(
                        temperature=0.2,
                        max_output_tokens=4096,
                    )
                    if system_instruction:
                        config.system_instruction = system_instruction

                    response = self._client.models.generate_content(
                        model=current_model,
                        contents=prompt,
                        config=config,
                    )

                    if response and response.text:
                        self._last_used_model = current_model
                        self._successful_calls += 1
                        logger.info("Gemini call succeeded with model %s", current_model)
                        return response.text.strip()
                    else:
                        raise GeminiProviderError("Empty response from Gemini")

                except GeminiProviderError:
                    raise
                except Exception as e:
                    last_error = e
                    error_str = str(e).lower()

                    # Don't retry on auth errors
                    if "api_key" in error_str or "unauthorized" in error_str or "403" in error_str:
                        raise GeminiProviderError(f"Authentication error: {e}")

                    # If model is unavailable (404/503) or quota exhausted (429), switch model immediately
                    if any(x in error_str for x in ("503", "404", "429", "resource_exhausted", "quota")):
                        logger.warning(
                            "Gemini model %s hit error (%s) — switching to next candidate model",
                            current_model, str(e)[:120],
                        )
                        break

                    # Retry on transient network errors
                    if attempt < max_retries - 1:
                        wait = min(2 ** attempt, 8)
                        logger.warning(
                            "Gemini attempt %d/%d (%s) failed: %s — retrying in %ds",
                            attempt + 1, max_retries, current_model, str(e), wait,
                        )
                        time.sleep(wait)

        raise GeminiProviderError(f"All model attempts failed. Last error: {last_error}")

    async def generate_structured(
        self,
        prompt: str,
        schema: Type[BaseModel],
        system_instruction: str | None = None,
    ) -> BaseModel:
        """
        Generate structured output and parse into a Pydantic model.
        """
        instruction = (system_instruction or "") + (
            f"\n\nRespond ONLY with valid JSON matching this schema:\n"
            f"{json.dumps(schema.model_json_schema(), indent=2)}"
        )

        raw = await self.generate(
            prompt=prompt,
            system_instruction=instruction.strip(),
        )

        # Try to extract JSON from the response
        json_str = raw
        if "```json" in raw:
            json_str = raw.split("```json")[1].split("```")[0].strip()
        elif "```" in raw:
            json_str = raw.split("```")[1].split("```")[0].strip()

        try:
            data = json.loads(json_str)
            return schema.model_validate(data)
        except (json.JSONDecodeError, Exception) as e:
            raise GeminiProviderError(f"Failed to parse Gemini response as {schema.__name__}: {e}")


class DemoProvider:
    """
    Deterministic provider for offline demo mode.
    Returns predefined synthetic data — clearly labeled as demo output.
    """

    @property
    def is_available(self) -> bool:
        return True  # always available

    @property
    def last_used_model(self) -> Optional[str]:
        return None

    @property
    def successful_calls(self) -> int:
        return 0

    async def generate(self, prompt: str, **kwargs) -> str:
        """Return deterministic demo text based on prompt keywords."""
        prompt_lower = prompt.lower()

        if "plan" in prompt_lower or "scope" in prompt_lower:
            return self._planning_response()
        elif "reconnais" in prompt_lower or "asset" in prompt_lower:
            return self._recon_response()
        elif "vulnerab" in prompt_lower or "weakness" in prompt_lower:
            return self._vulnerability_response()
        elif "valid" in prompt_lower or "evidence" in prompt_lower:
            return self._validation_response()
        elif "risk" in prompt_lower or "sever" in prompt_lower:
            return self._risk_response()
        elif "report" in prompt_lower or "summar" in prompt_lower:
            return self._report_response()
        else:
            return "[DEMO MODE] Synthetic analysis output for demonstration purposes."

    def _planning_response(self) -> str:
        return json.dumps({
            "plan_id": "demo-plan-001",
            "assessment_type": "full",
            "steps": [
                {"step": 1, "name": "Asset Discovery", "description": "Review supplied asset inventory"},
                {"step": 2, "name": "Configuration Review", "description": "Analyze configuration files for weaknesses"},
                {"step": 3, "name": "Dependency Audit", "description": "Check for known vulnerable dependencies"},
                {"step": 4, "name": "Access Control Review", "description": "Evaluate authentication and authorization"},
            ],
            "limitations": [
                "Demo mode — no live scanning performed",
                "Analysis based on synthetic evidence only",
                "Results are for demonstration purposes"
            ],
            "expected_outputs": ["findings_list", "risk_assessment", "remediation_plan"],
            "mode": "DEMO"
        })

    def _recon_response(self) -> str:
        return json.dumps({
            "observations": [
                {
                    "asset": "demo.lab.local",
                    "type": "web_application",
                    "technology_stack": ["Python", "Flask", "PostgreSQL"],
                    "open_ports": [80, 443, 5432],
                    "observations": "Web application with database backend. TLS configured.",
                    "source": "synthetic_inventory"
                },
                {
                    "asset": "api.lab.local",
                    "type": "api_server",
                    "technology_stack": ["Node.js", "Express"],
                    "open_ports": [443, 8080],
                    "observations": "REST API server. CORS headers present.",
                    "source": "synthetic_inventory"
                }
            ],
            "missing_information": [
                "Actual network topology not available in demo mode",
                "TLS certificate details not verified"
            ],
            "mode": "DEMO"
        })

    def _vulnerability_response(self) -> str:
        return json.dumps({
            "findings": [
                {
                    "title": "Outdated TLS Configuration",
                    "description": "The server supports TLS 1.0 and 1.1 which are deprecated. This could expose encrypted communications to downgrade attacks.",
                    "affected_asset": "demo.lab.local",
                    "severity": "medium",
                    "cwe_id": "CWE-326",
                    "confidence": "suspected",
                    "evidence": "Synthetic configuration review indicates TLS 1.0/1.1 support enabled",
                    "remediation": "Disable TLS 1.0 and 1.1. Enable only TLS 1.2+ with strong cipher suites.",
                    "source_type": "synthetic"
                },
                {
                    "title": "Missing Security Headers",
                    "description": "HTTP security headers (X-Frame-Options, X-Content-Type-Options, Content-Security-Policy) are not configured.",
                    "affected_asset": "demo.lab.local",
                    "severity": "low",
                    "cwe_id": "CWE-693",
                    "confidence": "suspected",
                    "evidence": "Synthetic HTTP response analysis shows missing security headers",
                    "remediation": "Add X-Frame-Options: DENY, X-Content-Type-Options: nosniff, and a restrictive Content-Security-Policy.",
                    "source_type": "synthetic"
                },
                {
                    "title": "Database Exposed to Non-Application Networks",
                    "description": "PostgreSQL port 5432 appears accessible from outside the application tier network segment.",
                    "affected_asset": "demo.lab.local:5432",
                    "severity": "high",
                    "cwe_id": "CWE-284",
                    "confidence": "suspected",
                    "evidence": "Synthetic network topology review indicates database port open to wider network",
                    "remediation": "Restrict database access to application-tier hosts only using firewall rules or network segmentation.",
                    "source_type": "synthetic"
                },
                {
                    "title": "Dependency with Known Vulnerability",
                    "description": "A project dependency (synthetic-lib v1.2.3) has a known remote code execution vulnerability.",
                    "affected_asset": "api.lab.local",
                    "severity": "critical",
                    "cwe_id": "CWE-1395",
                    "confidence": "suspected",
                    "evidence": "Synthetic dependency audit identified outdated package with known CVE",
                    "remediation": "Update synthetic-lib to version 1.2.5 or later which contains the security fix.",
                    "source_type": "synthetic"
                },
                {
                    "title": "Verbose Error Messages in API",
                    "description": "API error responses include stack traces and internal paths that could aid an attacker.",
                    "affected_asset": "api.lab.local",
                    "severity": "low",
                    "cwe_id": "CWE-209",
                    "confidence": "suspected",
                    "evidence": "Synthetic API response review shows detailed error messages",
                    "remediation": "Implement generic error responses in production. Log detailed errors server-side only.",
                    "source_type": "synthetic"
                }
            ],
            "mode": "DEMO"
        })

    def _validation_response(self) -> str:
        return json.dumps({
            "validation_results": [
                {"finding_title": "Outdated TLS Configuration", "status": "suspected", "notes": "Based on configuration review — not live-tested in demo mode"},
                {"finding_title": "Missing Security Headers", "status": "suspected", "notes": "Based on synthetic response analysis"},
                {"finding_title": "Database Exposed to Non-Application Networks", "status": "suspected", "notes": "Based on synthetic network topology — not verified with actual scan"},
                {"finding_title": "Dependency with Known Vulnerability", "status": "suspected", "notes": "Based on synthetic dependency audit data"},
                {"finding_title": "Verbose Error Messages in API", "status": "suspected", "notes": "Based on synthetic API response review"},
            ],
            "duplicates_found": 0,
            "contradictions": [],
            "missing_evidence": ["Live TLS scan results", "Actual HTTP response headers", "Real dependency manifest"],
            "mode": "DEMO"
        })

    def _risk_response(self) -> str:
        return json.dumps({
            "risk_assessment": [
                {"finding": "Dependency with Known Vulnerability", "severity": "critical", "rationale": "Remote code execution vulnerability in a dependency could allow full system compromise", "priority": 1},
                {"finding": "Database Exposed to Non-Application Networks", "severity": "high", "rationale": "Direct database access from untrusted networks enables data theft and manipulation", "priority": 2},
                {"finding": "Outdated TLS Configuration", "severity": "medium", "rationale": "Deprecated TLS versions vulnerable to known attacks, but exploitation requires network position", "priority": 3},
                {"finding": "Missing Security Headers", "severity": "low", "rationale": "Missing headers increase attack surface but require additional vulnerabilities to exploit", "priority": 4},
                {"finding": "Verbose Error Messages in API", "severity": "low", "rationale": "Information disclosure aids attackers but is not directly exploitable", "priority": 5},
            ],
            "overall_risk": "HIGH",
            "mode": "DEMO"
        })

    def _report_response(self) -> str:
        return (
            "[DEMO MODE — Synthetic Executive Summary]\n\n"
            "This security assessment was conducted in offline demonstration mode using synthetic evidence. "
            "The assessment identified 5 potential security findings across the target environment, including "
            "1 critical-severity issue related to a vulnerable dependency, 1 high-severity issue concerning "
            "database network exposure, 1 medium-severity issue with TLS configuration, and 2 low-severity "
            "informational findings.\n\n"
            "All findings are based on synthetic evidence and should be validated through actual security testing "
            "before remediation prioritization. The critical dependency vulnerability should be addressed immediately "
            "as it has the highest potential impact.\n\n"
            "LIMITATIONS: This report was generated in demo mode without live scanning or real evidence. "
            "All findings are synthetic and for demonstration purposes only."
        )


def get_llm_provider() -> GeminiProvider | DemoProvider:
    """Factory — returns the appropriate provider based on configuration."""
    settings = get_settings()
    if settings.is_demo_mode:
        return DemoProvider()
    return GeminiProvider()
