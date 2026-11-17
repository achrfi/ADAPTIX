"""Recompaction tests that call the code instead of reading its text.

These replaced assertions on ``inspect.getsource``. The old versions could not
tell a correct recompaction loop from a broken one, and they failed whenever the
source was merely reworded -- the exact false alarm seen twice after editing
``planner.py``. Everything below drives ``compact_context`` directly and
inspects what it returns.
"""

import copy
import json

import pytest

from src.adaptix.agents.context import compact_context


SYSTEM = 'You are a security agent. Answer only with a JSON action.'


def _count(system, prompt):
    """Token count stand-in: stable and monotonic in text length."""
    return len((system + prompt).split())


def _payload(scale=60):
    """A payload shaped like the one the planner actually compacts.

    Every key below is required by ``compact_context``: it trims only these
    collections, and every collection must be a list of JSON-able rows.
    """
    return {
        'user_request': 'scan the local juice shop',
        'authorization': {'type': 'signed_grant', 'token': 'grant-abc'},
        'scope_window': ['https://127.0.0.1:3000'],
        'services': [{'host': f'h{i}.local', 'port': 80} for i in range(scale)],
        'known_urls': [f'/api/item/{i}?q=probe{i}' for i in range(scale * 4)],
        'attempted_actions': [{'target': f'/api/item/{i}', 'status': 200}
                              for i in range(scale)],
        'rejected_actions': [{'target': f'/api/bad/{i}',
                             'reason': 'previously_rejected ' * 4} for i in range(scale)],
        'idor_findings': [{'id': i, 'endpoint': f'/api/item/{i}'} for i in range(scale)],
        'observations': {
            'notes': [f'observation {i} ' * 12 for i in range(scale)],
            'probes': [f'probe-{i}' for i in range(scale)],
        },
        'verified_findings': [],
        'budget': {'token_budget': 'unlimited'},
        'reflection': {'last_action': 'probe /status', 'note': 'keep going'},
        'recent_action_outcomes': [{'progress_reason': f'unchanged {i} ' * 6}
                                  for i in range(scale)],
        'tool_profiles': {'http_request': {'ok': 12}},
        'policy_feedback': [{'reason': 'stalled on /status ' * 4} for _ in range(8)],
        'stagnation': {'consecutive_infeasible_actions': 0},
        'domain_aliases': {'127.0.0.1': 'juice.local'},
        'discovery_limitations': [{'reason': f'limitation {i} ' * 6}
                                 for i in range(scale)],
        'available_endpoints': [f'/rest/item/{i}' for i in range(scale)],
        'tool_eligibility': {},
        'requested_endpoints': [],
        'web_route_summary': {},
        'documentation_attempts': [],
        'evidence_summary': {},
        'finding_escalation_policy': {},
        'scope_summary': {},
        'ffuf_import_summary': {},
        'controller_assessment': {},
        'identity_context_summary': {},
    }


def test_recompaction_shrinks_towards_a_reachable_target():
    """A reachable reduction must be produced, not merely attempted.

    The target sits below half the baseline, so summarising alone cannot satisfy
    it: the trimming helpers must run. The earlier version of this test used
    ``baseline // 2``, which the summarisation stages already met -- it passed
    even when every trimming helper was disabled.
    """
    payload = _payload()
    baseline = _count(SYSTEM, json.dumps(payload))
    target = 200

    prompt, metrics = compact_context(
        copy.deepcopy(payload), SYSTEM, target, _count, allow_over_budget=True)

    assert prompt is not None, 'a payload far above the target must be compactable'
    got = _count(SYSTEM, prompt)
    assert got < baseline, (
        'compaction returned a prompt no smaller than the input; the caller '
        'would resend the same oversized request')
    assert got <= target, (
        'compaction stopped at ' + str(got) + ' tokens against a reachable target '
        'of ' + str(target) + '; trimming is not running')
    assert metrics.get('context_compressed_tokens')


def test_compaction_reaches_its_floor_and_reports_it():
    """An impossible target proves the trimming helpers ran.

    Only real trimming gets from the baseline down to the floor, so this fails
    if any of them is disabled.
    """
    payload = _payload()
    baseline = _count(SYSTEM, json.dumps(payload))

    prompt, metrics = compact_context(
        copy.deepcopy(payload), SYSTEM, 1, _count, allow_over_budget=True)

    assert prompt is not None, 'permissive mode must return its best effort'
    floor = metrics.get('context_compressed_tokens')
    assert floor, 'the outcome must report where compaction landed'
    assert floor < baseline / 4, (
        'compaction only reached ' + str(floor) + ' tokens from a ' + str(baseline) +
        '-token input; the trimming helpers did not run')
    assert metrics.get('context_target_unreachable') is True


def test_strict_mode_refuses_what_permissive_mode_returns():
    """The two modes must differ in outcome, not in wording."""
    payload = _payload()
    strict, _ = compact_context(copy.deepcopy(payload), SYSTEM, 40, _count)
    permissive, metrics = compact_context(
        copy.deepcopy(payload), SYSTEM, 40, _count, allow_over_budget=True)

    assert strict is None, 'strict mode must refuse an unreachable target'
    assert permissive is not None, 'permissive mode must still return a best effort'
    assert metrics.get('context_target_unreachable') is True


def test_integrity_violation_is_refused_even_when_permissive():
    """Authoritative control data is never stripped -- proved by result.

    The old test searched the function text for ``intact()``. Here the control
    fields are present and must survive any permissive compaction.
    """
    payload = _payload()
    payload['authorization'] = {'grant': 'signed-grant-token-value'}
    payload['scope_window'] = ['https://127.0.0.1:3000']

    prompt, metrics = compact_context(
        copy.deepcopy(payload), SYSTEM, 40, _count, allow_over_budget=True)

    if prompt is None:
        assert metrics.get('context_integrity_violation') is True, (
            'a refusal must state why; a silent None hides the reason')
    else:
        for needle in ('signed-grant-token-value', '127.0.0.1:3000'):
            assert needle in prompt, (
                'permissive compaction returned a prompt that dropped '
                f'authoritative control data ({needle!r})')


def test_a_larger_target_compacts_less_or_equally():
    """Monotonicity: a looser budget must not produce a bigger prompt."""
    payload = _payload()
    tight, _ = compact_context(copy.deepcopy(payload), SYSTEM, 200, _count,
                               allow_over_budget=True)
    loose, _ = compact_context(copy.deepcopy(payload), SYSTEM, 600, _count,
                               allow_over_budget=True)

    if tight is not None and loose is not None:
        assert _count(SYSTEM, tight) <= _count(SYSTEM, loose) + 2, (
            'a looser token budget produced a larger prompt; the target is not '
            'being honoured')
