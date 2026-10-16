# SentinelAI — Interview Demonstration Walkthrough

This guide provides a scripted, zero-risk, step-by-step walkthrough suitable for an interview presentation. It proves that the platform satisfies all technical requirements, enforces boundaries, executes a 6-agent workflow, and generates executive deliverables.

---

## 1. Setup & Boot Sequence

### Step 1: Start the Backend & Dashboard
Open a terminal in the project root:
```bash
# Navigate to backend
cd backend

# Option A: Run directly with Python/uvicorn
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```
The terminal output will display:
```
============================================================
  SentinelAI starting up...
  Environment: development
  Demo mode: True
  Gemini configured: False (or True if GEMINI_API_KEY set)
  Database: SQLite
============================================================
INFO: Mounted frontend dashboard from .../frontend
```

### Step 2: Open Dashboard in Browser
Navigate to: **`http://localhost:8000/`** (or open `frontend/index.html` directly).

---

## 2. Live Demo Script

### Scene 1: Authentication & Role-Based Access Control (RBAC)
1. **Talking Point:** *"SentinelAI implements granular RBAC to separate duties across Admins, Analysts, and Viewers. Notice the quick-role buttons provided for zero-friction evaluation."*
2. Click the **Analyst** chip (`analyst` / `analyst123`) and click **Authenticate Session**.
3. Point out the top bar status badge: `Connected | analyst (analyst)`.

### Scene 2: Scope Enforcement & SSRF Shield
1. Click **Create Assessment**.
2. Set the Name to: `Live Boundary Verification Test`.
3. Try entering an unauthorized public IP in Authorized Targets: `8.8.8.8` or `169.254.169.254`.
4. Click **Create Assessment**.
5. **Observed Result:** The backend rejects the request with `400 Bad Request: Target 8.8.8.8 is outside the authorized lab scope`.
6. **Talking Point:** *"Notice that authorization decisions are never delegated to the LLM. Deterministic Python algorithms parse CIDRs and block SSRF vectors before any assessment is stored or scheduled."*

### Scene 3: Creating an Authorized Assessment
1. Enter permitted lab targets: `192.168.1.10:8080, 192.168.1.15:443`.
2. Check the scope attestation box: *"I attest that I have explicit authorization..."*.
3. Click **Create Assessment**.
4. The system navigates to the **Assessment Details** view.
5. Notice that the status is **`pending_approval`**.

### Scene 4: Human-in-the-Loop (HitL) Approval & Execution
1. Click the green **Approve Scope** button.
2. The status shifts to approved, and the **Run 6-Agent Workflow** button becomes active.
3. Click **Run 6-Agent Workflow**.
4. **Talking Point:** *"The workflow is now dispatched to LangGraph. Watch the Agent Orchestrator state card update dynamically through all six stages."*
5. Highlight the progression:
   - **Agent 1 (Scope & Planning):** Establishes boundaries and permitted checks.
   - **Agent 2 (Reconnaissance Analysis):** Processes safe synthetic telemetry.
   - **Agent 3 (Vulnerability Analysis):** Maps weaknesses to CWE identifiers (CWE-89, CWE-798, CWE-79).
   - **Agent 4 (Evidence Validation):** Flags duplicates and verifies findings against factual telemetry.
   - **Agent 5 (Risk Assessment):** Assigns deterministic CVSS ratings and remediation priorities (P0–P4).
   - **Agent 6 (Report Generation):** Produces the final executive report.

### Scene 5: Inspecting Deliverables & Reports
1. In the Assessment Details view, point out the **Findings Table** with severity pills (Critical, High, Medium, Low, Informational).
2. Click **Open Full HTML Report** &mdash; opens the formatted, executive-ready report in a new tab. Point out that all telemetry payloads are safely HTML-escaped.
3. Click **Download JSON** &mdash; inspect the structured output conforming to the Pydantic `ReportSchema`.

### Scene 6: Security Audit Trail
1. Sign out and sign in as **Admin** (`admin` / `admin123`).
2. Navigate to **Audit Logs**.
3. **Talking Point:** *"Notice the tamper-evident audit trail capturing every login, scope validation, approval, workflow execution, and report access event."*
