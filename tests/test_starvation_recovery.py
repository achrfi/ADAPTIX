"""A starved provider must get a smaller prompt on the retry, not the same one again.

Measured on `js-impact-161844` and `js-win-163243`: the ledger showed three requests at an
identical 31,799 / 31,819 provider tokens, all empty, and the pass died with
`planner_unavailable`. The retry existed but never ran, because the headroom line
subtracted from `window` — the scope window, a `list[str]` — instead of `context_window`.
That raised TypeError, the surrounding handler swallowed it, and every recompaction died
silently while the ledger recorded only the original oversized request.
"""
import inspect
import json

from src.adaptix.agents import planner
from src.adaptix.agents.context import compact_context


def test_headroom_uses_the_model_window_not_the_scope_window():
    source = inspect.getsource(planner.adaptive_planning)
    assert 'max(0, context_window - retry_cost)' in source
    # The scope-window name must never be used as a number.
    assert 'max(0, window - retry_cost)' not in source


def test_retry_reports_what_it_decided():
    """A skipped retry must be visible in metrics instead of silently absent."""
    source = inspect.getsource(planner.adaptive_planning)
    assert 'context_recompaction_attempted' in source


def test_retry_compaction_may_return_its_floor():
    """A floor above the requested target is still the only smaller prompt available."""
    source = inspect.getsource(planner.adaptive_planning)
    assert 'allow_over_budget=True' in source


def test_compaction_floor_is_returned_when_allowed():
    payload = {
        'user_request': 'probe the target', 'authorization': {'type': 'signed_grant'},
        'scope_window': ['http://h/a'], 'requested_endpoints': ['http://h/a'],
        'known_urls': ['http://h/p%d' % i for i in range(600)],
        'services': [{'host': 'h', 'port': 80, 'banner': 'y' * 60}] * 300,
        'attempted_actions': [{'tool': 'http_request', 'target': 'http://h/p%d' % i,
                               'reason': 'r%d' % i} for i in range(150)],
        'observations': {'web_routes': [{'url': 'http://h/r%d' % i} for i in range(600)]},
        'idor_findings': [], 'reflection': {'progress': 1}, 'budget': {},
        'tool_eligibility': {}, 'discovery_limitations': [],
        'web_route_summary': {'total': 600}, 'evidence_summary': {},
        'available_endpoints': [], 'scope_summary': {}, 'controller_assessment': {},
        'policy_feedback': [], 'rejected_actions': [], 'stagnation': {},
        'identity_context_summary': {}, 'domain_aliases': [],
    }
    system = 'S' * 3000
    count = lambda s, c: (len((s + c).encode('utf-8')) + 2) // 3
    baseline = count(system, json.dumps(payload))
    # A target far below the reachable floor: strict mode refuses, permissive returns it.
    strict, _ = compact_context(json.loads(json.dumps(payload)), system, 40, count)
    permissive, metrics = compact_context(json.loads(json.dumps(payload)), system, 40, count,
                                          allow_over_budget=True)
    assert strict is None
    assert permissive is not None
    assert count(system, permissive) < baseline
    assert metrics.get('context_target_unreachable') is True


def test_integrity_violation_still_refuses_even_when_permissive():
    """Stripping authoritative control data is never an acceptable answer."""
    source = inspect.getsource(compact_context)
    body = source.split('allow_over_budget')[0]
    assert 'intact()' in source
    assert 'context_integrity_violation' in source
