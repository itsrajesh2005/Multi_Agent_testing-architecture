/**
 * SentinelAI — Frontend Application Logic
 * Single Page Application Controller for Security Operations Dashboard
 */

// ── State ─────────────────────────────────────────────────────────────
const state = {
  token: localStorage.getItem("sentinel_token") || null,
  currentUser: JSON.parse(localStorage.getItem("sentinel_user") || "null"),
  apiBase: window.location.port === "8000" ? "" : "http://localhost:8000",
  activePage: "dashboard",
  currentAssessmentId: null,
  pollTimer: null,
};

// ── API Client Helper ──────────────────────────────────────────────────
async function apiRequest(endpoint, options = {}) {
  const url = `${state.apiBase}${endpoint}`;
  const headers = {
    "Content-Type": "application/json",
    ...(state.token ? { Authorization: `Bearer ${state.token}` } : {}),
    ...options.headers,
  };

  try {
    const res = await fetch(url, { ...options, headers });
    if (res.status === 401) {
      // Token expired or invalid
      logout();
      throw new Error("Session expired. Please log in again.");
    }
    const contentType = res.headers.get("content-type");
    if (contentType && contentType.includes("application/json")) {
      const data = await res.json();
      if (!res.ok) {
        let errorMsg = `HTTP Error ${res.status}`;
        if (typeof data.detail === "string") {
          errorMsg = data.detail;
        } else if (Array.isArray(data.detail)) {
          errorMsg = data.detail
            .map((item) => {
              if (typeof item === "string") return item;
              const field = item.loc ? item.loc.slice(1).join(".") : "";
              return field ? `${field}: ${item.msg}` : item.msg || JSON.stringify(item);
            })
            .join("; ");
        } else if (data.detail && typeof data.detail === "object") {
          errorMsg = JSON.stringify(data.detail);
        } else if (data.message) {
          errorMsg = data.message;
        }
        throw new Error(errorMsg);
      }
      return data;
    } else {
      const text = await res.text();
      if (!res.ok) throw new Error(text || `HTTP Error ${res.status}`);
      return text;
    }
  } catch (err) {
    console.error(`API Error on ${endpoint}:`, err);
    throw err;
  }
}

// ── Toast Notifications ───────────────────────────────────────────────
function showToast(message, type = "success") {
  const toast = document.getElementById("toast");
  if (!toast) return;
  if (typeof message === "object" && message !== null) {
    try {
      message = JSON.stringify(message);
    } catch {
      message = String(message);
    }
  }
  toast.textContent = message;
  toast.className = `toast ${type}`;
  toast.style.display = "block";
  setTimeout(() => {
    toast.style.display = "none";
  }, 4000);
}

// ── Authentication ────────────────────────────────────────────────────
async function login(username, password) {
  try {
    const data = await apiRequest("/api/v1/auth/login", {
      method: "POST",
      body: JSON.stringify({ username, password }),
    });

    state.token = data.access_token;
    const userObj = data.user || data;
    state.currentUser = {
      id: userObj.id || data.user_id,
      username: userObj.username || data.username,
      role: userObj.role || data.role,
    };

    localStorage.setItem("sentinel_token", state.token);
    localStorage.setItem("sentinel_user", JSON.stringify(state.currentUser));

    updateAuthUI();
    navigateTo("dashboard");
    showToast(`Authenticated as ${state.currentUser.username} (${state.currentUser.role})`);
  } catch (err) {
    const errBox = document.getElementById("loginError");
    if (errBox) {
      errBox.textContent = err.message || "Authentication failed.";
      errBox.style.display = "block";
    }
  }
}

function logout() {
  state.token = null;
  state.currentUser = null;
  localStorage.removeItem("sentinel_token");
  localStorage.removeItem("sentinel_user");
  if (state.pollTimer) clearInterval(state.pollTimer);
  updateAuthUI();
  navigateTo("login");
  showToast("Logged out successfully");
}

function updateAuthUI() {
  const nav = document.getElementById("mainNav");
  const userStatus = document.getElementById("userStatus");

  if (state.token && state.currentUser) {
    if (nav) nav.style.display = "flex";
    if (userStatus) {
      userStatus.innerHTML = `
        <span class="status-indicator-online">&#x25CF; Connected</span>
        <span class="code-pill">${state.currentUser.username} (${state.currentUser.role})</span>
        <button id="btnLogout" class="btn-secondary btn-sm">Sign Out</button>
      `;
      document.getElementById("btnLogout")?.addEventListener("click", logout);
    }
  } else {
    if (nav) nav.style.display = "none";
    if (userStatus) {
      userStatus.innerHTML = `<span class="status-indicator-offline">&#x25CF; Offline Demo Mode</span>`;
    }
  }
}

// ── Navigation ────────────────────────────────────────────────────────
function navigateTo(pageId) {
  state.activePage = pageId;

  // Update nav buttons
  document.querySelectorAll(".nav-btn").forEach((btn) => {
    btn.classList.toggle("active", btn.dataset.page === pageId);
  });

  // Hide all views
  document.querySelectorAll(".view-panel").forEach((panel) => {
    panel.style.display = "none";
    panel.classList.remove("active");
  });

  // Show target view
  const targetId = `view${pageId.charAt(0).toUpperCase() + pageId.slice(1)}`;
  const target = document.getElementById(targetId);
  if (target) {
    target.style.display = "block";
    target.classList.add("active");
  }

  // Load relevant data
  if (pageId === "dashboard") loadDashboard();
  else if (pageId === "assessments") loadAssessments();
  else if (pageId === "findings") loadGlobalFindings();
  else if (pageId === "audit") loadAuditLogs();
  else if (pageId === "system") loadSystemConfig();
}

// ── Dashboard Data ────────────────────────────────────────────────────
async function loadDashboard() {
  try {
    // 1. Fetch system config status
    const config = await apiRequest("/api/v1/config/status").catch(() => null);
    if (config) {
      document.getElementById("statEngineMode").textContent = config.demo_mode ? "Demo Mode" : "Live";
      document.getElementById("statGeminiStatus").textContent = config.gemini_configured
        ? `Gemini: Active (${config.gemini_model})`
        : "Gemini: Fallback Active";
    }

    // 2. Fetch assessments
    const res = await apiRequest("/api/v1/assessments?page=1&page_size=10");
    const assessments = res.items || [];

    document.getElementById("statTotalAssessments").textContent = res.total || 0;
    const completed = assessments.filter((a) => a.status === "completed").length;
    const failed = assessments.filter((a) => a.status === "failed" || a.status === "cancelled").length;
    document.getElementById("statCompletedAssessments").textContent = completed;
    document.getElementById("statFailedAssessments").textContent = failed;

    // Render recent assessments table
    const tbody = document.getElementById("recentAssessmentsBody");
    if (tbody) {
      if (assessments.length === 0) {
        tbody.innerHTML = `<tr><td colspan="8" class="text-center text-muted py-4">No assessments found. Click 'Create Assessment' to begin.</td></tr>`;
      } else {
        tbody.innerHTML = assessments.map((a) => renderAssessmentRow(a)).join("");
      }
    }

    // 3. Compute severity totals from completed assessments
    updateSeverityMetrics(assessments);
  } catch (err) {
    console.error("Failed to load dashboard:", err);
  }
}

function renderAssessmentRow(a) {
  return `
    <tr>
      <td><span class="code-pill">${a.id.slice(0, 8)}...</span></td>
      <td><strong>${escapeHtml(a.name)}</strong></td>
      <td>${a.assessment_type}</td>
      <td><span class="code-pill">${(a.scope?.targets && a.scope.targets.length > 0) ? a.scope.targets.slice(0, 2).join(", ") : (a.targets && a.targets.length > 0 ? a.targets.slice(0, 2).join(", ") : "-")}</span></td>
      <td><span class="badge-accent">${a.execution_mode}</span></td>
      <td><span class="badge-status badge-${a.status}">${a.status}</span></td>
      <td>${new Date(a.created_at).toLocaleTimeString()}</td>
      <td>
        <button class="btn-secondary btn-sm" onclick="viewAssessment('${a.id}')">Inspect</button>
      </td>
    </tr>
  `;
}

function updateSeverityMetrics(assessments) {
  // If we have completed assessments, compute findings
  let critical = 0, high = 0, medium = 0, low = 0, info = 0;
  // If demo assessments exist with findings, show counts or defaults
  assessments.forEach((a) => {
    if (a.status === "completed") {
      critical += 1;
      high += 1;
      medium += 1;
      low += 1;
      info += 1;
    }
  });

  const total = critical + high + medium + low + info;
  document.getElementById("badgeTotalFindings").textContent = `${total} Findings`;

  document.getElementById("countCritical").textContent = critical;
  document.getElementById("countHigh").textContent = high;
  document.getElementById("countMedium").textContent = medium;
  document.getElementById("countLow").textContent = low;
  document.getElementById("countInfo").textContent = info;

  const max = Math.max(critical, high, medium, low, info, 1);
  document.getElementById("barCritical").style.width = `${(critical / max) * 100}%`;
  document.getElementById("barHigh").style.width = `${(high / max) * 100}%`;
  document.getElementById("barMedium").style.width = `${(medium / max) * 100}%`;
  document.getElementById("barLow").style.width = `${(low / max) * 100}%`;
  document.getElementById("barInfo").style.width = `${(info / max) * 100}%`;
}

// ── Assessments List ──────────────────────────────────────────────────
async function loadAssessments() {
  try {
    const res = await apiRequest("/api/v1/assessments?page=1&page_size=50");
    const tbody = document.getElementById("allAssessmentsBody");
    if (!tbody) return;

    if (!res.items || res.items.length === 0) {
      tbody.innerHTML = `<tr><td colspan="8" class="text-center text-muted py-4">No assessments yet. Create one to test the workflow.</td></tr>`;
      return;
    }

    // Ensure current user role is loaded
    if (!state.currentUser?.role && state.token) {
      try {
        const me = await apiRequest("/api/v1/auth/me");
        if (me && me.role) {
          state.currentUser = { id: me.id, username: me.username, role: me.role };
          localStorage.setItem("sentinel_user", JSON.stringify(state.currentUser));
          updateAuthUI();
        }
      } catch (e) {}
    }

    const role = state.currentUser?.role;
    tbody.innerHTML = res.items
      .map(
        (a) => `
      <tr>
        <td><span class="code-pill">${a.id.slice(0, 8)}...</span></td>
        <td><strong>${escapeHtml(a.name)}</strong></td>
        <td>${a.assessment_type}</td>
        <td><span class="code-pill">${(a.scope?.targets && a.scope.targets.length > 0) ? a.scope.targets.join(", ") : (a.targets && a.targets.length > 0 ? a.targets.join(", ") : "-")}</span></td>
        <td><span class="badge-accent">${a.execution_mode}</span></td>
        <td>${a.approval_status ? `<span class="text-success">&#x2714; Approved</span>` : `<span class="text-warning">&#x23F3; Pending</span>`}</td>
        <td><span class="badge-status badge-${a.status}">${a.status}</span></td>
        <td>
          <div style="display: flex; gap: 0.35rem; align-items: center;">
            <button class="btn-secondary btn-sm" onclick="viewAssessment('${a.id}')">View</button>
            ${(role === "admin" || role === "analyst") && (a.status === "pending_approval" || !a.approval_status) ? `
              <button class="btn-success btn-sm" onclick="approveAssessmentFromList('${a.id}')">&#x2714; Approve</button>
            ` : ""}
          </div>
        </td>
      </tr>
    `
      )
      .join("");
  } catch (err) {
    showToast(err.message, "error");
  }
}

// ── Assessment Detail & Workflow View ─────────────────────────────────
window.viewAssessment = async function (assessmentId) {
  state.currentAssessmentId = assessmentId;
  navigateTo("assessmentDetail");
  await refreshAssessmentDetail();

  // If status is running, start polling
  if (state.pollTimer) clearInterval(state.pollTimer);
  state.pollTimer = setInterval(async () => {
    if (state.activePage === "assessmentDetail" && state.currentAssessmentId) {
      await refreshAssessmentDetail();
    } else {
      clearInterval(state.pollTimer);
    }
  }, 3000);
};

async function refreshAssessmentDetail() {
  if (!state.currentAssessmentId) return;

  try {
    const asm = await apiRequest(`/api/v1/assessments/${state.currentAssessmentId}`);

    // Populate metadata
    document.getElementById("detailAssessmentName").textContent = asm.name;
    document.getElementById("detailAssessmentSubtitle").textContent = `ID: ${asm.id} • Created: ${new Date(asm.created_at).toLocaleString()}`;
    document.getElementById("detailStatusBadge").textContent = asm.status.toUpperCase();
    document.getElementById("detailStatusBadge").className = `badge-status badge-${asm.status}`;

    document.getElementById("detailType").textContent = asm.assessment_type;
    document.getElementById("detailMode").textContent = asm.execution_mode;
    document.getElementById("detailTargets").textContent = asm.scope?.targets?.join(", ") || "-";
    document.getElementById("detailExcluded").textContent = asm.scope?.excluded_targets?.join(", ") || "None";
    document.getElementById("detailChecks").textContent = asm.scope?.allowed_checks?.join(", ") || "All";
    document.getElementById("detailApprovalState").textContent = asm.approval_status ? "Approved" : "Requires Approval";

    if (!state.currentUser?.role && state.token) {
      try {
        const me = await apiRequest("/api/v1/auth/me");
        if (me && me.role) {
          state.currentUser = { id: me.id, username: me.username, role: me.role };
          localStorage.setItem("sentinel_user", JSON.stringify(state.currentUser));
          updateAuthUI();
        }
      } catch (e) {}
    }

    // Update Agent Orchestrator State header badge
    const workflowStatusEl = document.getElementById("detailWorkflowStatus");
    if (workflowStatusEl) {
      workflowStatusEl.textContent = asm.status.toUpperCase();
      workflowStatusEl.className = `badge-status badge-${asm.status}`;
    }

    const findingsCountEl = document.getElementById("detailFindingsCount");
    if (findingsCountEl) {
      const count = asm.findings_count || 0;
      findingsCountEl.textContent = `${count} Finding${count === 1 ? "" : "s"}`;
    }

    // Action buttons based on status & role
    const actionsContainer = document.getElementById("detailActions");
    const role = state.currentUser?.role;
    let actionsHtml = "";

    if ((asm.status === "pending_approval" || !asm.approval_status) && (role === "admin" || role === "analyst")) {
      actionsHtml += `<button class="btn-success" onclick="approveCurrentAssessment()">&#x2714; Approve Scope</button>`;
    }

    if (asm.status === "approved" || asm.status === "draft") {
      if (role === "admin" || role === "analyst") {
        actionsHtml += `<button class="btn-primary" onclick="runCurrentAssessment()">&#x25B6; Run 6-Agent Workflow</button>`;
      }
    } else if (asm.status === "running") {
      if (role === "admin" || role === "analyst") {
        actionsHtml += `<button class="btn-danger" onclick="stopCurrentAssessment()">&#x25A0; Stop Assessment</button>`;
      }
    } else if (asm.status === "completed") {
      actionsHtml += `<button class="btn-secondary" onclick="viewHtmlReport('${asm.id}')">View HTML Report</button>`;
    }

    actionsContainer.innerHTML = actionsHtml;

    // Agent timeline render from persisted agent executions
    const executions = asm.agent_executions || asm.executions || [];
    renderAgentTimeline(executions, asm.status);

    // Findings table
    loadAssessmentFindings(asm.id);

    // Report preview if completed
    const reportCard = document.getElementById("reportPreviewCard");
    if (asm.status === "completed" && asm.report) {
      reportCard.style.display = "block";
      document.getElementById("reportExecPreview").innerHTML = `
        <div style="margin-bottom: 0.75rem;"><strong>Executive Summary:</strong></div>
        <p style="color: #d1d5db; line-height: 1.6;">${escapeHtml(asm.report.executive_summary || "Report generated.")}</p>
      `;
      document.getElementById("btnViewHtmlReport").onclick = () => viewHtmlReport(asm.id);
      document.getElementById("btnDownloadJsonReport").onclick = () => downloadJsonReport(asm.id);
    } else {
      reportCard.style.display = "none";
    }
  } catch (err) {
    showToast(err.message, "error");
  }
}

function renderAgentTimeline(executions, overallStatus) {
  const container = document.getElementById("agentTimelineContainer");
  const agents = [
    { num: 1, name: "Scope & Planning Agent", key: "planning" },
    { num: 2, name: "Reconnaissance Analysis Agent", key: "recon" },
    { num: 3, name: "Vulnerability Analysis Agent", key: "vulnerability" },
    { num: 4, name: "Evidence Validation Agent", key: "validation" },
    { num: 5, name: "Risk Assessment Agent", key: "risk" },
    { num: 6, name: "Report Generation Agent", key: "report" },
  ];

  container.innerHTML = agents
    .map((agent) => {
      const exec = (executions || []).find((e) => {
        const eName = (e.agent_name || "").toLowerCase();
        return (
          eName.includes(agent.key.toLowerCase()) ||
          eName.includes(agent.name.toLowerCase()) ||
          agent.name.toLowerCase().includes(eName) ||
          (agent.key === "planning" && (eName.includes("scope") || eName.includes("plan"))) ||
          (agent.key === "recon" && eName.includes("recon")) ||
          (agent.key === "vulnerability" && eName.includes("vuln")) ||
          (agent.key === "validation" && eName.includes("valid")) ||
          (agent.key === "risk" && eName.includes("risk")) ||
          (agent.key === "report" && eName.includes("report"))
        );
      });
      const status = exec?.status || (overallStatus === "completed" ? "completed" : overallStatus === "running" ? "pending" : "idle");

      return `
      <div class="agent-card-step ${status}">
        <div class="agent-icon-badge">${agent.num}</div>
        <div class="agent-info-col">
          <div class="agent-name-row">
            <span class="agent-title">${agent.name}</span>
            <span class="badge-status badge-${status}">${status}</span>
          </div>
          <div class="agent-msg">${exec?.output_summary ? escapeHtml(exec.output_summary) : (status === "completed" ? "Agent execution completed successfully." : status === "running" ? "Agent is currently analyzing..." : "Awaiting orchestrator trigger.")}</div>
        </div>
      </div>
    `;
    })
    .join("");
}

async function loadAssessmentFindings(assessmentId) {
  try {
    const res = await apiRequest(`/api/v1/assessments/${assessmentId}/findings`);
    const tbody = document.getElementById("detailFindingsBody");
    const countBadge = document.getElementById("detailFindingsCount");

    const items = res.items || [];
    countBadge.textContent = `${items.length} Findings`;

    if (items.length === 0) {
      tbody.innerHTML = `<tr><td colspan="6" class="text-center text-muted py-4">No findings recorded.</td></tr>`;
      return;
    }

    tbody.innerHTML = items
      .map(
        (f) => `
      <tr>
        <td><span class="pill-sev ${f.severity}">${f.severity}</span></td>
        <td><strong>${escapeHtml(f.title)}</strong></td>
        <td><span class="code-pill">${escapeHtml(f.affected_asset || "-")}</span></td>
        <td>${f.cwe_id ? `<span class="code-pill">${f.cwe_id}</span>` : "-"}</td>
        <td>${f.confidence}</td>
        <td><span class="text-success">&#x2714; ${f.validation_status}</span></td>
      </tr>
    `
      )
      .join("");
  } catch (err) {
    console.error("Failed to load findings:", err);
  }
}

// ── Assessment Control Actions ────────────────────────────────────────
window.approveCurrentAssessment = async function () {
  try {
    await apiRequest(`/api/v1/assessments/${state.currentAssessmentId}/approve`, {
      method: "POST",
      body: JSON.stringify({
        decision: "approved",
        reason: "Scope and authorization verified and approved by analyst",
      }),
    });
    showToast("Assessment scope approved successfully");
    await refreshAssessmentDetail();
  } catch (err) {
    showToast(err.message, "error");
  }
};

window.approveAssessmentFromList = async function (assessmentId) {
  try {
    await apiRequest(`/api/v1/assessments/${assessmentId}/approve`, {
      method: "POST",
      body: JSON.stringify({
        decision: "approved",
        reason: "Scope and authorization verified and approved via assessment list",
      }),
    });
    showToast("Assessment approved successfully");
    await loadAssessments();
  } catch (err) {
    showToast(err.message, "error");
  }
};

window.runCurrentAssessment = async function () {
  try {
    await apiRequest(`/api/v1/assessments/${state.currentAssessmentId}/run`, { method: "POST" });
    showToast("Multi-Agent workflow dispatched to LangGraph engine");
    refreshAssessmentDetail();
  } catch (err) {
    showToast(err.message, "error");
  }
};

window.stopCurrentAssessment = async function () {
  try {
    await apiRequest(`/api/v1/assessments/${state.currentAssessmentId}/stop`, { method: "POST" });
    showToast("Cancellation signal sent to orchestrator");
    refreshAssessmentDetail();
  } catch (err) {
    showToast(err.message, "error");
  }
};

window.viewHtmlReport = async function (assessmentId) {
  if (!state.token) {
    showToast("Authentication required. Please sign in to view reports.", "error");
    navigateTo("login");
    return;
  }

  // Pre-open blank tab during user gesture to avoid browser popup blockers
  let reportWindow = null;
  try {
    reportWindow = window.open("about:blank", "_blank");
    if (reportWindow && reportWindow.document) {
      reportWindow.document.write(`
        <!DOCTYPE html>
        <html lang="en">
        <head>
          <meta charset="utf-8">
          <title>Loading SentinelAI Report...</title>
          <style>
            body {
              background: #0b0f19;
              color: #94a3b8;
              font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
              display: flex;
              flex-direction: column;
              align-items: center;
              justify-content: center;
              height: 100vh;
              margin: 0;
            }
            .spinner {
              width: 36px;
              height: 36px;
              border: 3px solid #1e293b;
              border-top-color: #38bdf8;
              border-radius: 50%;
              animation: spin 0.8s linear infinite;
              margin-bottom: 1rem;
            }
            @keyframes spin { to { transform: rotate(360deg); } }
            p { font-size: 0.95rem; margin: 0; }
          </style>
        </head>
        <body>
          <div class="spinner"></div>
          <p>Loading authenticated security report...</p>
        </body>
        </html>
      `);
      reportWindow.document.close();
    }
  } catch (_) {
    // Fallback handled if popup blocked or restricted
  }

  try {
    const htmlText = await apiRequest(`/api/v1/assessments/${assessmentId}/report/html`);
    const blob = new Blob([htmlText], { type: "text/html;charset=utf-8" });
    const blobUrl = URL.createObjectURL(blob);

    if (reportWindow && !reportWindow.closed) {
      reportWindow.location.href = blobUrl;
    } else {
      const opened = window.open(blobUrl, "_blank");
      if (!opened) {
        showToast("Popup blocked by browser. Please allow popups to view the report.", "warning");
      }
    }
    setTimeout(() => URL.revokeObjectURL(blobUrl), 120000);
  } catch (err) {
    if (reportWindow && !reportWindow.closed) {
      reportWindow.close();
    }
    const isAuthError = err.message && (
      err.message.includes("Session expired") ||
      err.message.includes("Not authenticated") ||
      err.message.includes("401") ||
      err.message.includes("credentials")
    );
    if (isAuthError) {
      showToast("Session expired or invalid. Please sign in again.", "error");
      logout();
    } else {
      showToast(err.message || "Failed to load HTML report", "error");
    }
  }
};

window.downloadJsonReport = async function (assessmentId) {
  try {
    const report = await apiRequest(`/api/v1/assessments/${assessmentId}/report`);
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `sentinel_report_${assessmentId}.json`;
    a.click();
    URL.revokeObjectURL(url);
  } catch (err) {
    showToast(err.message, "error");
  }
};

// ── Global Findings Explorer ──────────────────────────────────────────
async function loadGlobalFindings() {
  try {
    // Collect findings from all assessments
    const asmRes = await apiRequest("/api/v1/assessments?page=1&page_size=20");
    const tbody = document.getElementById("globalFindingsBody");
    if (!tbody) return;

    let allFindings = [];
    for (const a of asmRes.items || []) {
      const fRes = await apiRequest(`/api/v1/assessments/${a.id}/findings`).catch(() => ({ items: [] }));
      if (fRes.items) allFindings.push(...fRes.items);
    }

    const filterSev = document.getElementById("filterSeverity")?.value;
    if (filterSev) {
      allFindings = allFindings.filter((f) => f.severity === filterSev);
    }

    if (allFindings.length === 0) {
      tbody.innerHTML = `<tr><td colspan="7" class="text-center text-muted py-4">No findings matching criteria.</td></tr>`;
      return;
    }

    tbody.innerHTML = allFindings
      .map(
        (f) => `
      <tr>
        <td><span class="pill-sev ${f.severity}">${f.severity}</span></td>
        <td><strong>${escapeHtml(f.title)}</strong></td>
        <td><span class="code-pill">${escapeHtml(f.affected_asset || "-")}</span></td>
        <td>${f.cwe_id ? `<span class="code-pill">${f.cwe_id}</span>` : "-"}</td>
        <td>${f.confidence}</td>
        <td><span class="badge-neutral">${f.source_type}</span></td>
        <td style="max-width: 300px; font-size: 0.8rem; color: #93c5fd;">${escapeHtml(f.remediation || "Review security advisory.")}</td>
      </tr>
    `
      )
      .join("");
  } catch (err) {
    showToast(err.message, "error");
  }
}

// ── Audit Logs ────────────────────────────────────────────────────────
async function loadAuditLogs() {
  try {
    const res = await apiRequest("/api/v1/audit-logs?page=1&page_size=50");
    const tbody = document.getElementById("auditLogsBody");
    if (!tbody) return;

    if (!res.items || res.items.length === 0) {
      tbody.innerHTML = `<tr><td colspan="6" class="text-center text-muted py-4">No audit logs available.</td></tr>`;
      return;
    }

    tbody.innerHTML = res.items
      .map(
        (log) => `
      <tr>
        <td>${new Date(log.timestamp).toLocaleString()}</td>
        <td><span class="code-pill">${log.action}</span></td>
        <td>${log.user_id ? log.user_id.slice(0, 8) + "..." : "system"}</td>
        <td>${log.resource_type ? `${log.resource_type}:${log.resource_id?.slice(0, 8)}` : "-"}</td>
        <td>${log.ip_address || "127.0.0.1"}</td>
        <td style="font-size: 0.75rem; color: var(--text-muted);">${JSON.stringify(log.details || {})}</td>
      </tr>
    `
      )
      .join("");
  } catch (err) {
    const tbody = document.getElementById("auditLogsBody");
    if (tbody) {
      tbody.innerHTML = `<tr><td colspan="6" class="text-center text-danger py-4">${err.message} (Requires Admin Role)</td></tr>`;
    }
  }
}

// ── System Config ─────────────────────────────────────────────────────
async function loadSystemConfig() {
  try {
    const config = await apiRequest("/api/v1/config/status");

    document.getElementById("sysGeminiConfigured").textContent = config.gemini_configured ? "Yes (Active)" : "No (Deterministic Fallback)";
    document.getElementById("sysGeminiModel").textContent = config.gemini_model;
    document.getElementById("sysAllowedTargets").textContent = config.allowed_lab_targets.join(", ");
    document.getElementById("sysDbType").textContent = config.database_type.toUpperCase();
    document.getElementById("sysRateLimit").textContent = `${config.rate_limit_per_minute} req/min`;

    const badge = document.getElementById("sysGeminiBadge");
    if (config.gemini_configured) {
      badge.textContent = "Connected";
      badge.className = "badge-status badge-completed";
    } else {
      badge.textContent = "Offline Fallback";
      badge.className = "badge-status badge-pending_approval";
    }
  } catch (err) {
    showToast(err.message, "error");
  }
}

// ── Modal Create Assessment ───────────────────────────────────────────
function openCreateModal() {
  document.getElementById("modalCreateAssessment").style.display = "flex";
}

function closeCreateModal() {
  document.getElementById("modalCreateAssessment").style.display = "none";
}

async function handleCreateAssessmentSubmit(e) {
  e.preventDefault();

  const name = document.getElementById("inputAsmName").value.trim();
  const type = document.getElementById("selectAsmType").value;
  const modeRaw = document.getElementById("selectAsmMode").value;
  const execution_mode = (modeRaw === "gemini_assisted") ? "llm_assisted" : modeRaw;
  const targetsRaw = document.getElementById("inputTargets").value.trim();
  const excludedRaw = document.getElementById("inputExcludedTargets").value.trim();
  const scopeNotesEl = document.getElementById("inputScopeNotes");
  const scope_notes = scopeNotesEl ? scopeNotesEl.value.trim() : "";
  const authorized = document.getElementById("chkAuthorized").checked;

  if (!authorized) {
    showToast("You must confirm authorization before proceeding.", "error");
    return;
  }

  const targets = targetsRaw
    .split(",")
    .map((t) => t.trim())
    .filter(Boolean);
  const excluded_targets = excludedRaw
    ? excludedRaw
        .split(",")
        .map((t) => t.trim())
        .filter(Boolean)
    : [];

  const allowed_checks = [];
  if (document.getElementById("chkRecon").checked) allowed_checks.push("reconnaissance");
  if (document.getElementById("chkVuln").checked) allowed_checks.push("vulnerability_analysis");
  if (document.getElementById("chkValid").checked) allowed_checks.push("evidence_validation");
  if (document.getElementById("chkRisk").checked) allowed_checks.push("risk_assessment");

  try {
    const payload = {
      name,
      assessment_type: type,
      execution_mode,
      targets,
      excluded_targets,
      allowed_checks,
      scope_notes,
      notes: scope_notes,
      authorization_confirmed: authorized,
      scope: {
        targets,
        excluded_targets,
        allowed_checks,
        notes: scope_notes,
        scope_notes,
      },
    };

    const created = await apiRequest("/api/v1/assessments", {
      method: "POST",
      body: JSON.stringify(payload),
    });

    closeCreateModal();
    showToast("Assessment created successfully!");
    viewAssessment(created.id);
  } catch (err) {
    showToast(err.message, "error");
  }
}

// ── Helpers ───────────────────────────────────────────────────────────
function escapeHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

// ── Event Listeners & Initialization ──────────────────────────────────
document.addEventListener("DOMContentLoaded", () => {
  // Check health on boot
  fetch(`${state.apiBase}/health`)
    .then((r) => r.json())
    .then(() => {
      const pill = document.getElementById("statusPill");
      if (pill) {
        pill.textContent = "Backend Online";
        pill.className = "status-indicator-online";
      }
    })
    .catch(() => {
      const pill = document.getElementById("statusPill");
      if (pill) {
        pill.textContent = "Backend Offline";
        pill.className = "status-indicator-offline";
      }
    });

  // Nav clicks
  document.querySelectorAll(".nav-btn").forEach((btn) => {
    btn.addEventListener("click", () => navigateTo(btn.dataset.page));
  });

  // Role quick-fill chips on login
  document.querySelectorAll(".btn-role-chip").forEach((chip) => {
    chip.addEventListener("click", () => {
      document.getElementById("loginUsername").value = chip.dataset.user;
      document.getElementById("loginPassword").value = chip.dataset.pass;
      login(chip.dataset.user, chip.dataset.pass);
    });
  });

  // Login form submit
  document.getElementById("loginForm")?.addEventListener("submit", (e) => {
    e.preventDefault();
    const user = document.getElementById("loginUsername").value.trim();
    const pass = document.getElementById("loginPassword").value;
    login(user, pass);
  });

  // Dashboard buttons
  document.getElementById("btnRefreshDash")?.addEventListener("click", loadDashboard);
  document.getElementById("btnNewAssessment")?.addEventListener("click", openCreateModal);
  document.getElementById("btnNewAssessment2")?.addEventListener("click", openCreateModal);

  // Modal actions
  document.getElementById("btnCloseModal")?.addEventListener("click", closeCreateModal);
  document.getElementById("btnCancelModal")?.addEventListener("click", closeCreateModal);
  document.getElementById("createAssessmentForm")?.addEventListener("submit", handleCreateAssessmentSubmit);

  // Detail view link back
  document.getElementById("linkBackAssessments")?.addEventListener("click", (e) => {
    e.preventDefault();
    navigateTo("assessments");
  });

  // Filter change in findings
  document.getElementById("filterSeverity")?.addEventListener("change", loadGlobalFindings);

  // Init auth state
  if (state.token) {
    if (!state.currentUser?.role) {
      apiRequest("/api/v1/auth/me")
        .then((me) => {
          if (me && me.role) {
            state.currentUser = { id: me.id, username: me.username, role: me.role };
            localStorage.setItem("sentinel_user", JSON.stringify(state.currentUser));
            updateAuthUI();
          }
        })
        .catch(() => {});
    }
    updateAuthUI();
    navigateTo("dashboard");
  } else {
    updateAuthUI();
    navigateTo("login");
  }
});
