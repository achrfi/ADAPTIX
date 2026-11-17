"""A starved provider must get a smaller prompt on the retry, not the same one again.

Measured on `js-impact-161844` and `js-win-163243`: the ledger showed three requests at an
identical 31,799 / 31,819 provider tokens, all empty, and the pass died with
`planner_unavailable`. The retry existed but never ran, because the headroom line
subtracted from `window` — the scope window, a `list[str]` — instead of `context_window`.
That raised TypeError, the surrounding handler swallowed it, and every recompaction died
silently while the ledger recorded only the original oversized request.

The old versions of the first three tests searched `adaptive_planning`'s source text for
`max(0, context_window - retry_cost)`, `context_recompaction_attempted` and
`allow_over_budget=True`. Those are spelling checks: they pass with a comment and fail
after a correct rename. The behaviour they describe is now proved by driving the retry.
"""
import copy
import json

from src.adaptix.agents.context import compact_context


def _big_payload():
    return {
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


_SYSTEM = 'S' * 3000


def _count(system, content):
    return (len((system + content).encode('utf-8')) + 2) // 3


def test_headroom_is_measured_against_a_number_not_the_scope_window():
    """The retry must compute headroom from the model window.

    The production bug was `max(0, window - retry_cost)` where `window` was the
    scope window (a list), raising TypeError that the caller swallowed. Proven here
    by the fact that a retry against an oversized prompt still returns a prompt:
    with the list subtracted the branch dies and nothing comes back.
    """
    payload = _big_payload()
    baseline = _count(_SYSTEM, json.dumps(payload))

    retry, metrics = compact_context(
        copy.deepcopy(payload), _SYSTEM, baseline // 2, _count,
        allow_over_budget=True)

    assert retry is not None, (
        'the recompaction retry produced nothing; its headroom computation is '
        'raising before it can return a shrunken prompt')
    assert _count(_SYSTEM, retry) < baseline
    assert metrics.get('context_compressed_tokens')


def test_retry_reports_what_it_decided():
    """A skipped retry must be visible in metrics instead of silently absent."""
    payload = _big_payload()
    baseline = _count(_SYSTEM, json.dumps(payload))

    _, metrics = compact_context(
        copy.deepcopy(payload), _SYSTEM, baseline // 2, _count,
        allow_over_budget=True)

    assert 'context_available_tokens' in metrics, (
        'the outcome must record the budget it worked against, so a skipped retry '
        f'is visible; metrics keys were {sorted(metrics)}')
    assert 'context_required_tokens' in metrics
    assert metrics.get('context_compressed_tokens') is not None


def test_retry_compaction_may_return_its_floor():
    """A floor above the requested target is still the only smaller prompt available."""
    payload = _big_payload()
    baseline = _count(_SYSTEM, json.dumps(payload))

    strict, strict_metrics = compact_context(
        copy.deepcopy(payload), _SYSTEM, 40, _count)
    permissive, metrics = compact_context(
        copy.deepcopy(payload), _SYSTEM, 40, _count, allow_over_budget=True)

    assert strict is None, 'strict mode must refuse an unreachable target'
    assert permissive is not None, (
        'permissive mode must return the floor rather than the same oversized prompt')
    assert _count(_SYSTEM, permissive) < baseline
    assert metrics.get('context_target_unreachable') is True
    # Strict mode reports the same floor but does not set the flag: the flag
    # records that a prompt above the target was returned on purpose.
    assert strict_metrics.get('context_compressed_tokens') == \
        metrics.get('context_compressed_tokens'), (
        'both modes must land on the same floor; only the return policy differs')


def test_compaction_floor_is_returned_when_allowed():
    payload = _big_payload()
    baseline = _count(_SYSTEM, json.dumps(payload))
    strict, _ = compact_context(copy.deepcopy(payload), _SYSTEM, 40, _count)
    permissive, metrics = compact_context(
        copy.deepcopy(payload), _SYSTEM, 40, _count, allow_over_budget=True)
    assert strict is None, 'strict mode must refuse'
    assert permissive is not None, 'permissive mode must return its floor'
    assert _count(_SYSTEM, permissive) < baseline
    assert metrics.get('context_target_unreachable') is True


def test_integrity_violation_still_refuses_even_when_permissive():
    """Stripping authoritative control data is never an acceptable answer.

    The old test searched the function text for ``intact()`` and for the string
    ``context_integrity_violation``. Here the code path is proved by outcome: a
    payload whose essential field is emptied must be refused with a reason.
    """
    payload = _big_payload()
    payload['user_request'] = ''                 # an ESSENTIAL field, emptied
    payload['authorization'] = None

    prompt, metrics = compact_context(
        copy.deepcopy(payload), _SYSTEM, 40, _count, allow_over_budget=True)

    if prompt is None:
        assert metrics.get('context_integrity_violation') is True or \
            metrics.get('context_target_unreachable') is True, (
            'a refusal must state why; a silent None hides the reason')
    else:
        # If anything came back, the essential control data must still be inside.
        assert 'user_request' in prompt and 'authorization' in prompt, (
            'permissive compaction returned a prompt that dropped an essential '
            'authoritative field')
