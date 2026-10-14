"""Single LangGraph with tool-by-tool planning, evidence processing, and bounded replanning."""
from typing import Any, TypedDict
from langgraph.graph import StateGraph, END
from src.adaptix.workflow.nodes import (
    scope_guard, reconnaissance, adaptive_planning, httpx_probe,
    nuclei_check, browser_observe, observation_processing,
    reflection_verification, state_update, final_report, blocked_report,
    advance_action, idor_test,
)
from src.adaptix.agents.planner import budget_exhausted


class AgentState(TypedDict, total=False):
    target: list[str] | str
    authorization_confirmed: bool
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
    actions = state.get('planned_actions', [])
    cursor = int(state.get('action_cursor', 0))
    if budget_exhausted(state) or cursor >= len(actions):
        return 'done'
    tool = actions[cursor].get('tool')
    return tool if tool in ('httpx', 'nuclei', 'playwright') else 'done'


def after_update(state):
    if state.get('stop_reason') or budget_exhausted(state):
        return 'report'
    # Avoid endless deterministic retries. Replan when the LLM can incorporate new observations.
    return 'replan' if state.get('planner_metrics', {}).get('mode') == 'llm' else 'report'


builder = StateGraph(AgentState)
for name, func in (
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
builder.add_edge('observation_processing', 'reflection_verification')
builder.add_edge('reflection_verification', 'state_update')
builder.add_conditional_edges('state_update', after_update,
                              {'replan': 'adaptive_planning', 'report': 'final_report'})
builder.add_edge('final_report', END)
builder.add_edge('blocked_report', END)
graph = builder.compile()
