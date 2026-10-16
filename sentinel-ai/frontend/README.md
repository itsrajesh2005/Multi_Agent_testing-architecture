# SentinelAI — Security Operations Frontend Dashboard

The SentinelAI frontend provides an intuitive, high-visibility dashboard for security analysts and auditors to coordinate, authorize, execute, and inspect multi-agent security assessment pipelines.

---

## Key Features

1. **Role-Based Operations:**
   - Quick sign-in chips for `admin`, `analyst`, and `viewer` roles to facilitate interview demos.
   - Dynamic UI gating (e.g., human-in-the-loop approval actions restricted to authorized roles, audit logs restricted to administrators).

2. **Real-Time Pipeline Tracking:**
   - Visual execution states for all 6 agents (Scope & Planning, Recon Analysis, Vulnerability Analysis, Evidence Validation, Risk Assessment, Report Generation).
   - Live polling for state updates during background workflow runs.

3. **Scope & Guardrail Visualization:**
   - Clear display of authorized target boundaries (CIDR/DNS lab allowlist).
   - Mandatory scope attestation checkbox during assessment creation.

4. **Multi-Artifact Delivery:**
   - Direct download of validated JSON reports (`ReportSchema`).
   - One-click launch of the sanitized, executive-ready HTML report.
   - Interactive Findings Explorer with severity filtering and remediation advice.

---

## Running the Frontend

### Option A: Integrated Mode (Zero-Dependency / Recommended)
The FastAPI backend is configured to serve the frontend directly at `http://localhost:8000/`. Simply boot the backend and navigate to the root URL in any modern browser.

### Option B: Standalone Node / Vite Dev Server
```bash
# Navigate to the frontend directory
cd frontend

# Install Vite dev dependencies
npm install

# Start the development server
npm run dev
```
Open `http://localhost:5173/` in your browser.
