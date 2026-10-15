"""Single LangGraph with tool-by-tool planning, evidence processing, and bounded replanning."""
from typing import Any, TypedDict
from langgraph.graph import StateGraph, END
from src.adaptix.workflow.nodes import (
    scope_guard, adaptive_planning, observation_processing,
    reflection_verification, state_update, final_report, blocked_report,
<<<<<<< HEAD
=======
    advance_action, idor_test,
>>>>>>> origin/main
)
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
    policy_replan_limit: int
    llm_temperature: float
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
    time_budget_seconds: float
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
    structured_observations: dict[str, Any]
    verified_findings: list[dict[str, Any]]
    rejected_findings: list[dict[str, Any]]
    inconclusive_findings: list[dict[str, Any]]
    stop_reason: str | None
    raw_bytes: int
    metrics: dict[str, Any]
    execution_metrics: dict[str, Any]
    iterations: int
    report: dict[str, Any]
    errors: list[str]
    events: list[str]
    max_iterations: int
    tool_call_budget: int
    token_budget: int
    planner_metrics: dict[str, Any]
    llm_model: str


def next_action(state):
    return 'done' if state.get('stop_reason') or budget_exhausted(state) or not state.get('planned_actions') else 'execute'


def after_update(state):
    return 'report' if state.get('stop_reason') or budget_exhausted(state) else 'replan'


from src.adaptix.workflow.nodes import execute_action
builder = StateGraph(AgentState)
for name, func in (
<<<<<<< HEAD
    ('scope_guard', scope_guard), ('adaptive_planning', adaptive_planning),
    ('execute_action', execute_action), ('observation_processing', observation_processing),
    ('reflection_verification', reflection_verification), ('state_update', state_update),
    ('final_report', final_report), ('blocked_report', blocked_report),
):
    builder.add_node(name, func)
builder.set_entry_point('scope_guard')
builder.add_conditional_edges('scope_guard', lambda s: 'blocked' if s.get('status') == 'scope_blocked' else 'approved',
                              {'blocked': 'blocked_report', 'approved': 'adaptive_planning'})
builder.add_conditional_edges('adaptive_planning', next_action, {'execute': 'execute_action', 'done': 'observation_processing'})
builder.add_edge('execute_action', 'observation_processing')
=======
    ('scope_guard', scope_guard), ('reconnaissance', reconnaissance),
    ('adaptive_planning', adaptive_planning), ('httpx', httpx_probe),
    ('nuclei', nuclei_check), ('playwright', browser_observe),
    ('advance_action', advance_action), ('idor_test', idor_test),
    ('observation_processing', observation_processing),
    ('reflection_verification', reflection_verification),
    ('state_update', state_update), ('final_report', final_report),
    ('blocked_report', blocked_report),
):
    builder.add_node(name, func)
builder.set_entry_point('scope_guard')
builder.add_conditional_edges('scope_guard',
                              lambda s: 'blocked' if s.get('status') == 'scope_blocked' else 'approved',
                              {'blocked': 'blocked_report', 'approved': 'reconnaissance'})
builder.add_edge('reconnaissance', 'adaptive_planning')
routes = {'httpx': 'httpx', 'nuclei': 'nuclei', 'playwright': 'playwright',
          'done': 'idor_test'}
builder.add_conditional_edges('adaptive_planning', next_action, routes)
for tool in ('httpx', 'nuclei', 'playwright'):
    builder.add_edge(tool, 'advance_action')
builder.add_conditional_edges('advance_action', next_action, routes)
builder.add_edge('idor_test', 'observation_processing')
>>>>>>> origin/main
builder.add_edge('observation_processing', 'reflection_verification')
builder.add_edge('reflection_verification', 'state_update')
builder.add_conditional_edges('state_update', after_update, {'replan': 'adaptive_planning', 'report': 'final_report'})
builder.add_edge('final_report', END)
builder.add_edge('blocked_report', END)
graph = builder.compile()
