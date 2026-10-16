# SentinelAI — Security Controls & Safety Architecture

## 1. Safety Principles

Autonomous AI security agents introduce severe operational hazards if not rigorously constrained. SentinelAI implements **Defense in Depth** across five distinct layers of enforcement.

```
+-----------------------------------------------------------+
| Layer 1: Identity & Role-Based Access Control (RBAC)      |
+-----------------------------------------------------------+
| Layer 2: Deterministic Scope & SSRF Prevention Engine     |
+-----------------------------------------------------------+
| Layer 3: Human-in-the-Loop (HitL) Authorization Gate      |
+-----------------------------------------------------------+
| Layer 4: Anti-Hallucination & Evidence Verification Gate  |
+-----------------------------------------------------------+
| Layer 5: Output Sanitization & Immutable Audit Trail      |
+-----------------------------------------------------------+
```

---

## 2. Detailed Control Specifications

### 2.1 Scope & SSRF Prevention Engine (`scope_validator.py`)
- **No Reliance on LLM:** Authorization and target parsing are handled exclusively by deterministic Python algorithms.
- **CIDR & Subnet Matching:** Targets are parsed into IP addresses and tested against `ALLOWED_LAB_TARGETS` using Python's standard `ipaddress` library.
- **Blocklist Enforcements:**
  - `127.0.0.0/8` and `::1` (Loopback): Denied by default to prevent internal service abuse.
  - `169.254.169.254` (Cloud Metadata): Denied to protect AWS/GCP/Azure IAM credentials.
  - Zero-address (`0.0.0.0`): Denied.
  - Multicast (`224.0.0.0/4`): Denied.
- **DNS Rebinding & Hostname Rules:** Hostnames must end with explicitly allowed lab suffixes (e.g., `.lab.local`).

### 2.2 Human-in-the-Loop (HitL) Authorization
- Assessments cannot transition directly from `draft` to `running`.
- If `REQUIRE_HUMAN_APPROVAL=true` (default), the assessment enters `pending_approval`.
- An authorized user with `analyst` or `admin` role must review the scope parameters and trigger `POST /api/v1/assessments/{id}/approve`.
- The approver's user ID, client IP, and approval timestamp are irreversibly recorded in the audit log and assessment record.

### 2.3 Kill Switch & Safe Cancellation (`orchestrator.py`)
- Every running workflow checks an active cancellation flag before entering each agent node.
- A user can trigger `POST /api/v1/assessments/{id}/stop` at any time.
- The orchestrator gracefully halts at the current node transition, sets status to `cancelled`, and persists the partial execution trail without leaving orphan processes.

### 2.4 Evidence Validation (Anti-Hallucination Guard)
- LLMs frequently invent realistic-sounding CVEs, CWEs, or exploit strings when prompted about vulnerabilities.
- Agent 4 evaluates candidate findings against the factual telemetry collected by Agent 2.
- Rules:
  - If a finding references an asset not present in the reconnaissance observations, it is flagged.
  - If a finding claims a confirmed SQL injection without HTTP response error or timing anomaly in the evidence, its confidence is downgraded to `unverified`.
  - Duplicate findings with identical CWEs and assets are consolidated to prevent report inflation.

### 2.5 Output Sanitization & HTML Escaping
- Vulnerability reports often reflect raw payloads such as `<script>alert(1)</script>`.
- If unescaped, an attacker could achieve Stored XSS inside the security dashboard or HTML report.
- The Report Generator applies contextual HTML entity escaping (`html.escape(quote=True)`) to all titles, descriptions, evidence payloads, and remediation instructions prior to embedding in HTML templates.

### 2.6 Tamper-Evident Audit Logging
- Every security-relevant event produces an `AuditLog` row:
  - `LOGIN`, `LOGIN_FAILED`
  - `ASSESSMENT_CREATED`, `ASSESSMENT_APPROVED`
  - `ASSESSMENT_STARTED`, `ASSESSMENT_COMPLETED`, `ASSESSMENT_STOPPED`, `ASSESSMENT_FAILED`
  - `REPORT_GENERATED`, `REPORT_ACCESSED`
- Audit logs contain the user ID, timestamp, client IP, and contextual metadata, and cannot be modified or deleted via the API.
