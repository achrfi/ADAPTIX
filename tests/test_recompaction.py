"""Recompaction must reduce the prompt, using the reduction actually reachable.

Measured on `js-impact-155547`: the local payload was 10,764 tokens but the gateway
reported 30,110 — it injects ~19.3k of its own system prompt. Starvation became
deterministic above ~31.6k, so the only useful lever is the payload we control.

The retry targeted `max(2 * smallest, window * 0.5)` = 32,768, larger than the prompt
itself, so `compact_context` returned the identical string, the guard rejected it, and
recompaction never ran. A fixed 60% target then landed *below* the compaction floor and
also returned None. The target is now prompt-relative and stepped.
"""
import inspect

from src.adaptix.agents import planner
from src.adaptix.agents.context import compact_context


def test_the_target_is_derived_from_the_prompt_not_the_window():
    source = inspect.getsource(planner.adaptive_planning)
    assert 'int(compacted * fraction)' in source
    assert 'int(context_window * 0.5)' not in source


def test_several_fractions_are_tried():
    """A single fixed fraction can land under the floor and silently skip the retry."""
    source = inspect.getsource(planner.adaptive_planning)
    assert 'for fraction in (' in source
    fractions = source.split('for fraction in (')[1].split(')')[0]
    assert fractions.count(',') >= 2, fractions


def test_the_first_fraction_asks_for_a_real_reduction():
    """The retry must ask for a meaningfully smaller prompt than it just sent."""
    source = inspect.getsource(planner.adaptive_planning)
    fractions = source.split('for fraction in (')[1].split(')')[0]
    values = [float(v) for v in fractions.split(',')]
    assert values[0] <= 0.8, values
    assert values == sorted(values), 'fractions should relax, not tighten: %s' % values


def test_compaction_actually_shrinks_a_realistic_payload():
    """The guard only accepts a genuinely smaller prompt; prove one exists."""
    payload = {
        'user_request': 'x' * 200, 'authorization': {'type': 'signed_grant'},
        'scope_window': ['http://h/a'] * 40, 'requested_endpoints': ['http://h/a'] * 40,
        'known_urls': ['http://h/p%d' % i for i in range(400)],
        'services': [{'host': 'h', 'port': 80, 'banner': 'y' * 80}] * 200,
        'attempted_actions': [{'tool': 'http_request', 'target': 'http://h/p%d' % i,
                               'reason': 'probe %d' % i} for i in range(120)],
        'observations': {'web_routes': [{'url': 'http://h/r%d' % i} for i in range(400)]},
        'idor_findings': [], 'reflection': {'progress': 1}, 'budget': {},
        'tool_eligibility': {}, 'discovery_limitations': [],
        'web_route_summary': {'total': 400}, 'evidence_summary': {},
        'available_endpoints': [], 'scope_summary': {}, 'controller_assessment': {},
    }
    system = 'S' * 4000
    count = lambda s, c: (len((s + c).encode('utf-8')) + 2) // 3
    baseline = count(system, __import__('json').dumps(payload))
    out, _ = compact_context(__import__('json').loads(__import__('json').dumps(payload)),
                             system, int(baseline * 0.80), count)
    assert out is not None
    assert count(system, out) < baseline
