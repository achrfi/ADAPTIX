"""Execution limits independent from model-token accounting.

Budget convention: every configured cumulative limit (tokens, seconds,
tool calls, iterations) is either a positive number or ``None``. ``None``
is the internal representation of an operator-chosen unlimited budget; the
CLI word for it is ``unlimited``. No consumer may substitute a large
convenience number for ``None`` - an arbitrary number is a different,
finite budget. Absent keys keep their historical finite defaults so older
state dicts and program callers keep working unchanged.

Unlimited only removes cumulative ceilings; per-request/per-call timeouts,
rate limits, concurrency controls, provider response caps, the model's own
context window and all security guardrails stay in force, and every
consumption axis keeps being metered either way.
"""

UNLIMITED_WORD = 'unlimited'
# Historical finite defaults for state dicts that predate unlimited support.
DEFAULT_TOOL_CALL_BUDGET = 20
DEFAULT_TIME_BUDGET_SECONDS = 1800.0
DEFAULT_TOKEN_BUDGET = 50_000
DEFAULT_MAX_ITERATIONS = 20
# Memory-safety bounds that are not budgets: bounded stores stay bounded even
# when the run has no cumulative ceiling.
STORE_CACHE_BOUND = 512


def parse_budget(value, caster):
    """Normalize one CLI budget value.

    ``unlimited`` (case-insensitive) becomes ``None``; numeric strings are
    cast; anything else raises ``ValueError`` with an operator-readable
    message for argparse to surface. Numbers pass through unchanged.
    """
    if isinstance(value, str):
        if value.strip().lower() == UNLIMITED_WORD:
            return None
        try:
            return caster(value.strip())
        except ValueError as exc:
            raise ValueError(f"budget value {value!r} is not 'unlimited' or a positive number") from exc
    return caster(value)


def budget_limit(state, key, default):
    """Configured limit for ``key``: ``None`` when unlimited, int otherwise.

    An absent key falls back to the historical finite ``default`` so partial
    state dicts and test states keep working; an explicitly configured
    ``None`` means the operator removed the ceiling.
    """
    value = state.get(key, default)
    if value is None:
        return None
    try:
        number = int(value)
    except (TypeError, ValueError):
        number = int(default)
    return number


def time_budget_finite(state):
    return budget_limit(state, 'time_budget_seconds', DEFAULT_TIME_BUDGET_SECONDS) is not None


def token_budget_finite(state):
    return budget_limit(state, 'token_budget', DEFAULT_TOKEN_BUDGET) is not None


def tool_budget_finite(state):
    return budget_limit(state, 'tool_call_budget', DEFAULT_TOOL_CALL_BUDGET) is not None


def iterations_finite(state):
    return budget_limit(state, 'max_iterations', DEFAULT_MAX_ITERATIONS) is not None


def unlimited_keys(state):
    """Names of the configured cumulative budgets that are unlimited right now."""
    names = []
    if not token_budget_finite(state):
        names.append('token_budget')
    if not time_budget_finite(state):
        names.append('time_budget_seconds')
    if not tool_budget_finite(state):
        names.append('tool_call_budget')
    if not iterations_finite(state):
        names.append('max_iterations')
    return names


def remaining_seconds(state):
    """Wall-clock seconds left in the run; infinity when the time budget is unlimited."""
    import time
    budget = state.get('time_budget_seconds', DEFAULT_TIME_BUDGET_SECONDS)
    if budget is None:
        return float('inf')
    return max(0.0, float(budget) - (time.time() - float(state.get('run_started_at', time.time()))))


def remaining_tokens(state, tokens_used):
    """Cumulative planner tokens still spendable; ``None`` when the budget is unlimited."""
    limit = budget_limit(state, 'token_budget', DEFAULT_TOKEN_BUDGET)
    if limit is None:
        return None
    return max(0, limit - int(tokens_used))


def tool_calls_used(state):
    return int(state.get('execution_metrics', {}).get('tool_calls_used', 0))


def tool_budget_available(state):
    limit = budget_limit(state, 'tool_call_budget', DEFAULT_TOOL_CALL_BUDGET)
    if limit is None:
        return True
    return tool_calls_used(state) < limit


def record_tool_call(state, name):
    metrics = dict(state.get('execution_metrics', {}))
    by_tool = dict(metrics.get('by_tool', {}))
    by_tool[name] = int(by_tool.get(name, 0)) + 1
    metrics['by_tool'] = by_tool
    metrics['tool_calls_used'] = int(metrics.get('tool_calls_used', 0)) + 1
    return metrics


def tool_timeout(state, default):
    return max(0.001, min(float(default), remaining_seconds(state)))


def unlimited_remote_risk(model, api_base, api_key):
    """True when the run's provider is remote or paid, per operator-provided facts.

    Only the operator's own configuration answers this: an API key marks a paid
    provider, and a non-loopback api_base marks a remote endpoint. The default
    local routing (Ollama on the same machine) is explicitly not flagged.
    """
    import os
    from urllib.parse import urlsplit
    if api_key:
        return True
    api_base = api_base or os.getenv('ADAPTIX_API_BASE')
    if api_key is None and os.getenv('ADAPTIX_API_KEY'):
        return True
    if not api_base:
        return False
    try:
        host = urlsplit(str(api_base)).hostname or ''
    except ValueError:
        return True
    if host in ('localhost', '127.0.0.1', '::1') or host.endswith('.localhost'):
        return False
    return True
