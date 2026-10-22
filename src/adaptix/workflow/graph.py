"""Single LangGraph with tool-by-tool planning, evidence processing, and bounded replanning."""
from typing import Any, TypedDict
from langgraph.graph import StateGraph, END
from src.adaptix.workflow.nodes import (
    scope_guard, adaptive_planning, observation_processing,
    reflection_verification, state_update, final_report, blocked_report,
)
from src.adaptix.workflow.baseline import baseline_reconnaissance
from src.adaptix.workflow.scanner import nuclei_scan
from src.adaptix.agents.planner import budget_exhausted


class AgentState(TypedDict, total=False):
    identity_context: dict[str, Any]
    api_observations: list[dict[str, Any]]
    api_operations: list[dict[str, Any]]
    scenario_candidates: list[dict[str, Any]]
    scenario_validations: list[dict[str, Any]]
    discovery_limitations: list[dict[str, Any]]
    rejected_actions: list[dict[str, Any]]
    recon_inventory: list[dict[str, Any]]
    planner_cache: dict[str, Any]
    planner_retry_limit: int
    consecutive_policy_rejections: int
    consecutive_infeasible_actions: int
    consecutive_no_gain_passes: int
    fixated_targets: tuple | None
    infeasible_stop_limit: int
    consecutive_provider_failures: int
    provider_failure_limit: int
    consecutive_schema_failures: int
    schema_failure_limit: int
    consecutive_empty_plans: int
    empty_plan_limit: int
    policy_replan_limit: int
    llm_temperature: float
    llm_timeout_seconds: float
    model_context_tokens: int
    token_ledger: list[dict[str, Any]]
    tool_catalog: dict[str, Any]
    action_approvals: list[str]
    approval_audit: list[dict[str, Any]]
    lab_manifest: dict[str, Any]
    artifact_bundle: dict[str, Any]
    checkpoint_ref: str
    scope_manifest: dict[str, Any]
    scope_networks: list[str]
    scope_touched: list[str]
    scope_deferred: list[str]
    scope_window: list[str]
    planning_history: list[dict[str, Any]]
    candidate_assessments: list[dict[str, Any]]
    tool_profiles: dict[str, Any]
    action_outcomes: list[dict[str, Any]]
    run_started_at: float
    time_budget_seconds: float | None
    user_prompt: str
    reflection: dict[str, Any]
    reflection_assessment: dict[str, Any] | None
    recent_evidence_keys: list[str]
    objective_kind: str
    policy_feedback: list[dict[str, Any]]
    reflection_history: list[dict[str, Any]]
    target: list[str] | str
    scope_aliases: dict[str, list[str]]
    scope_ports: list[int]
    grant: str
    principal: str
    authorization: dict[str, Any]
    run_id: str
    status: str
    hosts: list[str]
    services: list[dict[str, Any]]
    planned_urls: list[str]
    planned_actions: list[dict[str, Any]]
    action_cursor: int
    attempted_actions: list[dict[str, Any]]
    http_services: list[dict[str, Any]]
    candidates: list[dict[str, Any]]
    nuclei_template_selections: list[dict[str, Any]]
    verification_evidence: list[dict[str, Any]]
    browser_evidence: list[dict[str, Any]]
    idor_scenarios: list[dict[str, Any]]
    idor_findings: list[dict[str, Any]]
    web_routes: list[dict[str, Any]]
    discovered_documents: list[str]
    probe_traces: list[dict[str, Any]]
    request_audit: list[dict[str, Any]]
    hypotheses: list[dict[str, Any]]
    findings: list[dict[str, Any]]
    structured_observations: dict[str, Any]
    verified_findings: list[dict[str, Any]]
    nuclei_observations: list[dict[str, Any]]
    markdown_report: str
    rejected_findings: list[dict[str, Any]]
    inconclusive_findings: list[dict[str, Any]]
    stop_reason: str | None
    raw_bytes: int
    metrics: dict[str, Any]
    execution_metrics: dict[str, Any]
    baseline_recon: dict[str, Any]
    baseline_metrics: dict[str, Any]
    baseline_disabled: bool
    scanner_assessment: bool
    nuclei_scan: dict[str, Any]
    nuclei_scan_metrics: dict[str, Any]
    scanner_disabled: bool
    iterations: int
    phase_runtime: list[dict[str, Any]]
    report: dict[str, Any]
    errors: list[str]
    events: list[str]
    max_iterations: int | None
    tool_call_budget: int | None
    token_budget: int | None
    planner_metrics: dict[str, Any]
    llm_model: str


def next_action(state):
    return 'done' if state.get('stop_reason') or budget_exhausted(state) or not state.get('planned_actions') else 'execute'


def after_update(state):
    return 'report' if state.get('stop_reason') or budget_exhausted(state) else 'replan'


from src.adaptix.workflow.nodes import execute_action
builder = StateGraph(AgentState)
import time as _time


def _timed(name, func):
    """Record each workflow phase's wall time so unexplained stalls are visible.

    The row says which phase ran, when (run-pass index) and how long it took; a
    missing phase between two rows of a pass is itself attribution evidence.
    """
    def wrapped(state):
        started = _time.monotonic()
        out = func(state)
        duration = round(_time.monotonic() - started, 3)
        out = {**out}
        rows = list(out.get('phase_runtime', []))
        if state.get('phase_runtime'):
            rows = [*state['phase_runtime'], *rows]
        rows.append({'pass': int(state.get('iterations', 0)), 'phase': name, 'seconds': duration})
        out['phase_runtime'] = rows
        return out
    return wrapped


for name, func in (
    ('scope_guard', scope_guard), ('baseline_reconnaissance', baseline_reconnaissance),
    ('nuclei_scan', nuclei_scan), ('adaptive_planning', adaptive_planning),
    ('execute_action', execute_action), ('observation_processing', observation_processing),
    ('reflection_verification', reflection_verification), ('state_update', state_update),
    ('final_report', final_report), ('blocked_report', blocked_report),
):
    builder.add_node(name, _timed(name, func))
builder.set_entry_point('scope_guard')
builder.add_conditional_edges('scope_guard', lambda s: 'blocked' if s.get('status') == 'scope_blocked' else 'baseline',
                              {'blocked': 'blocked_report', 'baseline': 'baseline_reconnaissance'})
# The baseline and the scanner phase inline the deterministic observation
# processing (dedupe and structured inventory) before handing straight to the
# model: no phase teleports through the reflection/state-update loop that
# belongs to executed actions.
builder.add_edge('baseline_reconnaissance', 'nuclei_scan')
builder.add_edge('nuclei_scan', 'adaptive_planning')
builder.add_conditional_edges('adaptive_planning', next_action, {'execute': 'execute_action', 'done': 'observation_processing'})
builder.add_edge('execute_action', 'observation_processing')
builder.add_edge('observation_processing', 'reflection_verification')
builder.add_edge('reflection_verification', 'state_update')
builder.add_conditional_edges('state_update', after_update, {'replan': 'adaptive_planning', 'report': 'final_report'})
builder.add_edge('final_report', END)
builder.add_edge('blocked_report', END)
graph = builder.compile()
