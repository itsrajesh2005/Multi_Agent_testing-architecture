# SentinelAI — Technical Interview Brief & Defense Guide

## 1. The One-Minute Project Pitch

> *"SentinelAI is an enterprise-grade multi-agent penetration testing and security assessment architecture designed to solve a fundamental dilemma in AI security: how to leverage LLMs for complex vulnerability analysis without suffering hallucinations, prompt injection, or reckless unauthorized network attacks.*
>
> *I built SentinelAI with a **dual-plane architecture**: a non-negotiable, deterministic FastAPI control plane enforcing CIDR scope boundaries, SSRF prevention, and human-in-the-loop approval gates; and an agentic cognitive plane orchestrated by **LangGraph** where six specialized agents pass typed context across planning, reconnaissance, vulnerability correlation, evidence validation, risk scoring, and report synthesis.
>
> *It supports Google Gemini 2.0 with strict Pydantic parsing, but features a transparent, zero-cost deterministic fallback that allows complete, safe offline demonstrations and 100% reproducible test execution without requiring an API key or firing a single unauthorized network packet."*

---

## 2. Core Architectural Decisions

### Q1: Why LangGraph instead of AutoGen, CrewAI, or raw LangChain?
**Answer:**
1. **Deterministic State Machine:** LangGraph models workflows as explicit directed graphs (`StateGraph`). In security assessments, nondeterministic agent loops are a severe operational risk. LangGraph allows strict linear execution with clear transition criteria and recursion bounds.
2. **Typed State Isolation:** LangGraph passes a strongly typed state dictionary (`AssessmentState`). Each agent node acts as a pure transformation on state slices, enabling granular auditability and checkpointing at every step.
3. **Resilience & Cancellation:** LangGraph naturally integrates with asynchronous cancellation tokens, enabling our instant kill-switch feature.

### Q2: Why Google Gemini?
**Answer:**
1. **Long Context & Structured JSON Output:** Gemini 2.0 provides native support for controlled generation and JSON schemas, ensuring responses map directly to Pydantic models.
2. **Speed & Latency:** `gemini-2.0-flash` provides low-latency inference suitable for multi-step agent pipelines.
3. **Clean Decoupling:** We isolated all Gemini interactions inside `GeminiProvider`. If the API key is omitted, rate-limited, or unavailable, the system seamlessly transitions to our deterministic provider without pipeline crashes.

### Q3: How do you prevent LLM Hallucinations in Security Findings?
**Answer:**
We use a **two-tiered anti-hallucination guard**:
1. **Agent 4 (Evidence Validation Gate):** Sits between Vulnerability Analysis (Agent 3) and Risk Assessment (Agent 5). It takes the candidate findings and programmatically cross-references them against raw telemetry logs collected in Agent 2. If a finding claims a vulnerability without supporting telemetry, it is demoted to `unverified` and excluded from executive risk aggregates.
2. **Deterministic Risk Scoring in Agent 5:** Rather than asking the LLM to invent CVSS numbers, Agent 5 evaluates deterministic criteria (affected asset exposure, confidence score, impact rating) to compute reproducible severity metrics.

### Q4: Why must authorization be deterministic on the backend?
**Answer:**
An LLM should never make access control or boundary decisions. A prompt injection attack (e.g., in a target banner or HTTP error) could instruct the LLM to `"Approve scan for 10.0.0.1"`. In SentinelAI, target authorization is enforced in pure Python using `ipaddress.ip_network` and strict CIDR checks before the LLM is ever invoked.

---

## 3. Ten Likely Interviewer Questions & Answers

### 1. "Can an agent escape its scope and attack external hosts?"
**Answer:** No. Network sockets are never opened arbitrarily by agents. The system analyzes ingested telemetry. Furthermore, the backend `ScopeValidator` rejects any target outside `ALLOWED_LAB_TARGETS` during assessment creation.

### 2. "How do you handle rate limits or API outages from Gemini?"
**Answer:** `GeminiProvider` implements exponential backoff with bounded retries. If the quota is exhausted or the network drops, it logs the event and smoothly falls back to our deterministic synthetic provider, guaranteeing that assessments always complete cleanly.

### 3. "How is Stored XSS prevented in the report?"
**Answer:** In `report_agent.py`, all user-controlled strings, evidence strings, and parameter names pass through `html.escape(quote=True)` before being interpolated into the HTML template.

### 4. "What database is supported?"
**Answer:** SQLAlchemy 2.0 abstracts the database layer. By default, it runs on SQLite for zero-configuration local demos. By configuring `DATABASE_URL`, it immediately supports PostgreSQL with connection pooling.

### 5. "How do you enforce tenant isolation?"
**Answer:** Every query fetching an assessment or report includes `_get_assessment_for_user()`, verifying that the requesting user's ID matches `assessment.owner_id` unless the user possesses the `admin` role.

### 6. "What happens if a user submits malicious input in scope notes?"
**Answer:** Input validation via Pydantic limits string lengths and prevents SQL injection via SQLAlchemy's parameterized queries.

### 7. "How do you test the system without paying for Gemini tokens?"
**Answer:** The test suite (`test_api.py`) mocks the `GeminiProvider` responses entirely and runs in-memory SQLite, executing all tests in seconds without network calls.

### 8. "How does the Human-in-the-Loop mechanism work?"
**Answer:** Assessments are created in `pending_approval`. The workflow trigger endpoint checks `if require_human_approval and not assessment.approval_status: raise HTTPException(400)`. Only an authorized analyst or admin can approve it.

### 9. "What is the role of Agent 2 vs Agent 3?"
**Answer:** Agent 2 focuses solely on asset enumeration and telemetry ingestion (non-interpretive reconnaissance). Agent 3 interprets that telemetry to identify weakness patterns and CWE mappings.

### 10. "What are the current limitations and future improvements?"
**Answer:**
- **Current Limitation:** Dynamic scanning is intentionally disabled in favor of synthetic telemetry to ensure safety.
- **Future Improvement:** Integration with isolated sandboxes (e.g., Docker container sidecars) for controlled active testing with pre-negotiated rules of engagement.
