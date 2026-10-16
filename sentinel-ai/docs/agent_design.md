# SentinelAI — Multi-Agent System Design

## 1. Architectural Philosophy

The core principle of SentinelAI is **Specialized Division of Labor**. Rather than having a monolithic agent that performs all tasks using one generic prompt, the system breaks the assessment lifecycle into **six specialized, verifiable agents** orchestrated by **LangGraph**.

```
[Start] --> Agent 1: Scope & Planning
                 |
                 v
            Agent 2: Reconnaissance Analysis
                 |
                 v
            Agent 3: Vulnerability Analysis
                 |
                 v
            Agent 4: Evidence Validation (Anti-Hallucination Gate)
                 |
                 v
            Agent 5: Risk Assessment (Deterministic CVSS)
                 |
                 v
            Agent 6: Report Generation (JSON & Sanitized HTML)
                 |
               [End]
```

---

## 2. Agent Specifications

### Agent 1: Scope & Planning Agent (`planning_agent.py`)
- **Input:** `assessment_name`, `assessment_type`, `targets`, `excluded_targets`, `allowed_checks`, `scope_notes`.
- **Primary Responsibility:**
  - Decomposes assessment scope into ordered execution phases.
  - Verifies targets against permitted assessment types.
  - Rejects any out-of-scope test requests before telemetry analysis begins.
- **Restrictions:** Cannot expand target lists or bypass exclusions.
- **Output:** `planning_summary`, `plan_steps`, `permitted_checks`.
- **Failure Handling:** If targets are unparseable, marks state `failed` and terminates the pipeline immediately.

### Agent 2: Reconnaissance Analysis Agent (`recon_agent.py`)
- **Input:** Target scope and permitted reconnaissance checks.
- **Primary Responsibility:**
  - Evaluates asset inventory metadata and telemetry.
  - Identifies exposed ports, open endpoints, software banners, and missing perimeter controls.
  - Formulates structured observations with explicit source provenance.
- **Restrictions:** Strictly non-intrusive. Never scans arbitrary public internet IPs. Uses synthetic telemetry in demo mode.
- **Output:** `recon_observations`, `attack_surface_summary`.
- **Failure Handling:** Returns fallback synthetic telemetry if Gemini API is unreachable.

### Agent 3: Vulnerability Analysis Agent (`vulnerability_agent.py`)
- **Input:** Reconnaissance observations and asset telemetry.
- **Primary Responsibility:**
  - Correlates observed configurations against known vulnerability patterns.
  - Maps potential weaknesses to official MITRE CWE identifiers (e.g., CWE-89, CWE-79, CWE-798).
  - Generates provisional severity hypotheses with technical justification.
- **Restrictions:** Autonomous exploitation, credential attacks, persistence, and destructive actions are prohibited by design.
- **Output:** `candidate_findings` (unvalidated list of vulnerability hypotheses).
- **Failure Handling:** If model returns invalid JSON, schema parser recovers structured fields or uses verified synthetic candidates.

### Agent 4: Evidence Validation Agent (`validation_agent.py`)
- **Input:** `candidate_findings` and raw telemetry evidence.
- **Primary Responsibility (Anti-Hallucination Guard):**
  - Cross-references every candidate finding against factual telemetry evidence.
  - Detects duplicate findings (e.g., overlapping endpoints or multiple reports of the same misconfiguration).
  - Flags contradictory or unsupported claims.
  - Classifies each finding: `confirmed`, `suspected`, or `unverified`.
- **Restrictions:** Does not assign final risk scores; focuses strictly on evidentiary integrity.
- **Output:** `validated_findings`, `deduplication_summary`.
- **Failure Handling:** Defaults to `unverified` if evidence source is ambiguous.

### Agent 5: Risk Assessment Agent (`risk_agent.py`)
- **Input:** `validated_findings` and asset criticality metadata.
- **Primary Responsibility:**
  - Evaluates business impact, network exposure, and attacker effort.
  - Assigns deterministic severity ratings: `Critical`, `High`, `Medium`, `Low`, `Informational`.
  - Establishes prioritized remediation schedule (P0 Immediate to P4 Low).
  - Preserves CVSS base scoring criteria without inventing arbitrary numbers.
- **Restrictions:** Cannot alter findings evidence; only grades risk and prioritizes remediation.
- **Output:** `risk_assessed_findings`, `severity_summary`, `remediation_priorities`.
- **Failure Handling:** Falls back to deterministic heuristic risk matrix if LLM reasoning times out.

### Agent 6: Report Generation Agent (`report_agent.py`)
- **Input:** Fully validated and scored findings, scope metadata, and methodology notes.
- **Primary Responsibility:**
  - Synthesizes executive summary tailored for C-suite and technical leadership.
  - Compiles structured JSON artifact conforming to `ReportSchema`.
  - Generates standalone, styled HTML report with contextual entity escaping to prevent stored XSS.
  - Highlights assessment limitations and non-goals.
- **Restrictions:** Cannot add new findings or alter severity ratings. Must strictly escape all user-controllable input strings.
- **Output:** `executive_summary`, `methodology`, `report_json`, `report_html`, `report_limitations`.
- **Failure Handling:** Produces clean deterministic template output if LLM synthesis fails.

---

## 3. LangGraph Orchestrator Integration

- **State Schema:** Inherits from `TypedDict` (`AssessmentState`) with typed fields for every agent stage.
- **Sequential Edge Flow:**
  `planning_node` &rarr; `recon_node` &rarr; `vuln_node` &rarr; `validation_node` &rarr; `risk_node` &rarr; `report_node`.
- **State Logging:** At every step transition, an `AgentExecution` entity is saved to the database capturing timestamp, duration, status, and summary output, providing full auditability in the UI dashboard.
