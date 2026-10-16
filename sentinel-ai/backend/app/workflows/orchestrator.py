"""
LangGraph orchestrator — builds and runs the multi-agent assessment workflow.

The workflow graph:
    planning → recon → vulnerability → validation → risk → report

Each node is an agent function that reads from and writes to the shared
AssessmentState. The orchestrator manages execution order, error handling,
cancellation, and persistence of agent results to the database.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from langgraph.graph import StateGraph, END

from app.agents.state import AssessmentState
from app.agents.planning_agent import planning_agent
from app.agents.recon_agent import recon_agent
from app.agents.vulnerability_agent import vulnerability_agent
from app.agents.validation_agent import validation_agent
from app.agents.risk_agent import risk_agent
from app.agents.report_agent import report_agent

logger = logging.getLogger("sentinel_ai.orchestrator")

# Track running assessments for cancellation
_running_assessments: Dict[str, bool] = {}

# Agent definitions with their step order
AGENTS = [
    {"name": "Scope & Planning", "key": "planning", "func": planning_agent, "order": 1},
    {"name": "Reconnaissance", "key": "recon", "func": recon_agent, "order": 2},
    {"name": "Vulnerability Analysis", "key": "vulnerability", "func": vulnerability_agent, "order": 3},
    {"name": "Evidence Validation", "key": "validation", "func": validation_agent, "order": 4},
    {"name": "Risk Assessment", "key": "risk", "func": risk_agent, "order": 5},
    {"name": "Report Generation", "key": "report", "func": report_agent, "order": 6},
]


def _should_continue(state: AssessmentState) -> str:
    """Conditional edge — check if workflow should continue or stop."""
    if state.get("is_cancelled"):
        return "end"
    if state.get("workflow_status") == "failed":
        return "end"
    return "continue"


def build_workflow_graph() -> StateGraph:
    """
    Build the LangGraph workflow graph with all six agents.

    Graph structure:
        planning → check → recon → check → vulnerability → check →
        validation → check → risk → check → report → END
    """
    graph = StateGraph(AssessmentState)

    # Add agent nodes
    graph.add_node("planning", planning_agent)
    graph.add_node("recon", recon_agent)
    graph.add_node("vulnerability", vulnerability_agent)
    graph.add_node("validation", validation_agent)
    graph.add_node("risk", risk_agent)
    graph.add_node("report", report_agent)

    # Set entry point
    graph.set_entry_point("planning")

    # Add edges with conditional checks
    graph.add_conditional_edges(
        "planning",
        _should_continue,
        {"continue": "recon", "end": END},
    )
    graph.add_conditional_edges(
        "recon",
        _should_continue,
        {"continue": "vulnerability", "end": END},
    )
    graph.add_conditional_edges(
        "vulnerability",
        _should_continue,
        {"continue": "validation", "end": END},
    )
    graph.add_conditional_edges(
        "validation",
        _should_continue,
        {"continue": "risk", "end": END},
    )
    graph.add_conditional_edges(
        "risk",
        _should_continue,
        {"continue": "report", "end": END},
    )
    graph.add_edge("report", END)

    return graph


async def run_assessment_workflow(
    assessment_id: str,
    assessment_name: str,
    assessment_type: str,
    execution_mode: str,
    targets: list[str],
    excluded_targets: list[str] | None = None,
    allowed_checks: list[str] | None = None,
    scope_notes: str | None = None,
    db_session=None,
) -> AssessmentState:
    """
    Execute the full multi-agent assessment workflow.

    Args:
        assessment_id: Unique assessment ID
        assessment_name: Human-readable name
        assessment_type: Type of assessment
        execution_mode: 'demo' or 'llm_assisted'
        targets: List of authorized targets
        excluded_targets: Optional excluded targets
        allowed_checks: Optional specific checks to perform
        scope_notes: Optional scope notes
        db_session: Optional database session for persisting results

    Returns:
        Final AssessmentState with all agent outputs
    """
    logger.info("Starting assessment workflow: %s (%s, mode=%s)", assessment_name, assessment_id, execution_mode)

    # Register for cancellation tracking
    _running_assessments[assessment_id] = False

    # Filter targets against excluded targets
    excluded_set = set(t.strip().lower() for t in (excluded_targets or []))
    sanitized_targets = [t for t in targets if t.strip().lower() not in excluded_set]

    # Build initial state
    initial_state: AssessmentState = {
        "assessment_id": assessment_id,
        "assessment_name": assessment_name,
        "assessment_type": assessment_type,
        "execution_mode": execution_mode,
        "targets": sanitized_targets,
        "excluded_targets": excluded_targets or [],
        "allowed_checks": allowed_checks or [],
        "scope_notes": scope_notes,
        "errors": [],
        "is_cancelled": False,
        "workflow_status": "running",
        "current_agent": "",
    }

    # Build and compile the graph
    graph = build_workflow_graph()
    compiled = graph.compile()

    # Persist agent execution records if DB session available
    if db_session:
        _create_agent_execution_records(db_session, assessment_id, execution_mode)
        _update_agent_status(db_session, assessment_id, "planning", "running")

    next_agent_map = {
        "planning": "recon",
        "recon": "vulnerability",
        "vulnerability": "validation",
        "validation": "risk",
        "risk": "report",
    }

    try:
        # Run the graph and accumulate state updates from all steps
        current_state = dict(initial_state)

        async for step in compiled.astream(initial_state):
            # Check for cancellation
            if _running_assessments.get(assessment_id):
                logger.info("Assessment %s cancelled", assessment_id)
                current_state["is_cancelled"] = True
                current_state["workflow_status"] = "cancelled"
                break

            # Accumulate state from each executed agent node
            for node_name, node_output in step.items():
                if isinstance(node_output, dict):
                    current_state.update(node_output)
                    current_agent = node_output.get("current_agent", node_name)
                    if current_agent and db_session:
                        f_count = len(
                            current_state.get("risk_assessed_findings")
                            or current_state.get("validated_findings")
                            or current_state.get("raw_findings")
                            or []
                        )
                        summary = None
                        if node_name == "planning":
                            steps_count = len(current_state.get("plan_steps", []))
                            summary = f"Security plan created with {steps_count} steps."
                        elif node_name == "recon":
                            obs_count = len(current_state.get("recon_observations", []))
                            summary = f"Gathered {obs_count} asset observations."
                        elif node_name == "vulnerability":
                            raw_count = len(current_state.get("raw_findings", []))
                            summary = f"Identified {raw_count} potential vulnerabilities."
                        elif node_name == "validation":
                            val_count = len(current_state.get("validated_findings", []))
                            dups = current_state.get("duplicates_found", 0)
                            summary = f"Validated {val_count} findings ({dups} duplicates filtered)."
                        elif node_name == "risk":
                            risk_val = current_state.get("overall_risk", "UNKNOWN").upper()
                            summary = f"Risk rating determined: {risk_val}."
                        elif node_name == "report":
                            summary = "Executive summary, HTML report, and JSON report generated."

                        _update_agent_status(
                            db_session,
                            assessment_id,
                            current_agent,
                            "completed",
                            output_summary=summary,
                            findings_count=f_count,
                        )

                        next_node = next_agent_map.get(current_agent)
                        if next_node:
                            _update_agent_status(db_session, assessment_id, next_node, "running")

                    logger.info("Agent '%s' completed for assessment %s", current_agent, assessment_id)

        final_state = current_state
        if not final_state.get("workflow_status"):
            final_state["workflow_status"] = "completed"

        logger.info("Assessment workflow %s finished: status=%s", assessment_id, final_state.get("workflow_status"))

    except Exception as e:
        logger.error("Assessment workflow %s failed: %s", assessment_id, str(e))
        final_state = initial_state
        final_state["workflow_status"] = "failed"
        final_state["errors"] = [str(e)]
        if db_session:
            current_ag = final_state.get("current_agent") or "planning"
            _update_agent_status(db_session, assessment_id, current_ag, "failed", error_message=str(e))

    finally:
        _running_assessments.pop(assessment_id, None)

    return final_state


def cancel_assessment(assessment_id: str) -> bool:
    """Request cancellation of a running assessment."""
    if assessment_id in _running_assessments:
        _running_assessments[assessment_id] = True
        logger.info("Cancellation requested for assessment %s", assessment_id)
        return True
    return False


def is_assessment_running(assessment_id: str) -> bool:
    """Check if an assessment is currently running."""
    return assessment_id in _running_assessments


def _create_agent_execution_records(db_session, assessment_id: str, execution_mode: str):
    """Create or reset AgentExecution records in the database for tracking."""
    from app.models import AgentExecution, AgentStatus, ExecutionMode

    existing = (
        db_session.query(AgentExecution)
        .filter(AgentExecution.assessment_id == assessment_id)
        .all()
    )
    if existing:
        for rec in existing:
            rec.status = AgentStatus.PENDING
            rec.execution_mode = ExecutionMode(execution_mode)
            rec.started_at = None
            rec.completed_at = None
            rec.output_summary = None
            rec.findings_count = 0
            rec.error_message = None
        db_session.commit()
        return

    for agent in AGENTS:
        exec_record = AgentExecution(
            assessment_id=assessment_id,
            agent_name=agent["name"],
            step_order=agent["order"],
            status=AgentStatus.PENDING,
            execution_mode=ExecutionMode(execution_mode),
        )
        db_session.add(exec_record)
    db_session.commit()


def _update_agent_status(
    db_session,
    assessment_id: str,
    agent_key: str,
    status: str,
    output_summary: str | None = None,
    findings_count: int = 0,
    error_message: str | None = None,
):
    """Update the status of an agent execution record."""
    from app.models import AgentExecution, AgentStatus

    # Map agent key to name
    agent_name_map = {a["key"]: a["name"] for a in AGENTS}
    name = agent_name_map.get(agent_key, agent_key)

    record = (
        db_session.query(AgentExecution)
        .filter(AgentExecution.assessment_id == assessment_id, AgentExecution.agent_name == name)
        .first()
    )
    if record:
        record.status = AgentStatus(status)
        now = datetime.now(timezone.utc)
        if status == "running" and not record.started_at:
            record.started_at = now
        elif status in ("completed", "failed"):
            if not record.started_at:
                record.started_at = now
            record.completed_at = now
        if output_summary:
            record.output_summary = output_summary
        if findings_count:
            record.findings_count = findings_count
        if error_message:
            record.error_message = error_message
        db_session.commit()
