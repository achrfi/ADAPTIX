"""ADAPTIX unified main workflow: one graph, one codebase."""
from typing import Any, TypedDict
from langgraph.graph import StateGraph, END
from src.adaptix.workflow.nodes import (scope_guard, reconnaissance, adaptive_planning, httpx_probe,
                    nuclei_check, browser_observe, observation_processing,
                    reflection_verification, state_update, final_report, blocked_report)


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
    http_services: list[dict[str, Any]]
    candidates: list[dict[str, Any]]
    browser_evidence: list[dict[str, Any]]
    structured_observations: dict[str, Any]
    verified_findings: list[dict[str, Any]]
    rejected_findings: list[dict[str, Any]]
    inconclusive_findings: list[dict[str, Any]]
    stop_reason: str
    raw_bytes: int
    metrics: dict[str, Any]
    iterations: int
    report: dict[str, Any]
    errors: list[str]
    events: list[str]
    max_iterations: int
    tool_call_budget: int
    token_budget: int
    planner_metrics: dict[str, Any]
    llm_model: str


builder = StateGraph(AgentState)
for name, func in (
    ('scope_guard', scope_guard), ('reconnaissance', reconnaissance),
    ('adaptive_planning', adaptive_planning), ('httpx', httpx_probe),
    ('nuclei', nuclei_check), ('playwright', browser_observe),
    ('observation_processing', observation_processing),
    ('reflection_verification', reflection_verification),
    ('state_update', state_update), ('final_report', final_report),
    ('blocked_report', blocked_report)
):
    builder.add_node(name, func)
builder.set_entry_point('scope_guard')
builder.add_conditional_edges('scope_guard',
                              lambda s: 'blocked' if s.get('status') == 'scope_blocked' else 'approved',
                              {'blocked': 'blocked_report', 'approved': 'reconnaissance'})
chain = ('reconnaissance', 'adaptive_planning', 'httpx', 'nuclei', 'playwright',
         'observation_processing', 'reflection_verification', 'state_update', 'final_report')
for left, right in zip(chain, chain[1:]):
    builder.add_edge(left, right)
builder.add_edge('final_report', END)
builder.add_edge('blocked_report', END)
graph = builder.compile()
