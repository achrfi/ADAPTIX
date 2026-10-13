"""Execution limits independent from model-token accounting."""


def tool_budget_available(state):
    used = int(state.get('execution_metrics', {}).get('tool_calls_used', 0))
    return used < int(state.get('tool_call_budget', 20))


def record_tool_call(state, name):
    metrics = dict(state.get('execution_metrics', {}))
    by_tool = dict(metrics.get('by_tool', {}))
    by_tool[name] = int(by_tool.get(name, 0)) + 1
    metrics['by_tool'] = by_tool
    metrics['tool_calls_used'] = int(metrics.get('tool_calls_used', 0)) + 1
    return metrics
