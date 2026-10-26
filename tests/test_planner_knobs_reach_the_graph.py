"""Every provider/planner knob must survive the graph state schema.

LangGraph validates state against the ``GraphState`` TypedDict and silently drops
keys it does not declare. This has now cost two debugging rounds: first a hosted
provider ran with no base URL or key, then ``llm_reasoning_effort`` was discarded
so a reasoning model kept returning empty content and every planning pass failed
with ``ValidationError`` - while the same checkpoint replayed outside the graph
succeeded.

The fix is unglamorous: declare every key. The test is what stops the next one.
"""
import pytest

from src.adaptix.workflow.graph import AgentState

# Keys main.py writes into the run state that must reach the planner.
PLANNER_INPUT_KEYS = (
    'llm_model',
    'llm_api_base',
    'llm_api_key',
    'llm_native_json',
    'llm_reasoning_effort',
    'llm_temperature',
    'llm_timeout_seconds',
    'model_context_tokens',
    'planner_retry_limit',
    'time_budget_seconds',
    'tool_call_budget',
    'token_budget',
    'report_model_enabled',
)


@pytest.mark.parametrize('key', PLANNER_INPUT_KEYS)
def test_planner_knob_is_declared_in_graph_state(key):
    annotations = AgentState.__annotations__
    assert key in annotations, (
        f'{key} is written into the run state but not declared in AgentState, so '
        'LangGraph drops it before the planner reads it')


def test_reasoning_effort_is_reachable_from_the_planner():
    """The planner must be able to read the knob, not just declare it."""
    import inspect

    from src.adaptix.agents import planner

    source = inspect.getsource(planner)
    assert "state.get('llm_reasoning_effort')" in source, (
        'the planner must honour an operator reasoning_effort setting')
    assert "kwargs['reasoning_effort']" in source, (
        'the planner must send reasoning_effort on the provider call')
