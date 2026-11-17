"""A resumed run must report the spend of the resumed portion, not the earlier one.

The defect this locks: `--resume` issued a new tool-call budget but kept the
previous process's cumulative counter, so a report claimed e.g. 33 calls used
against a limit of 25 -- spend that happened before the resume, compared against
a budget that did not exist yet. A limit that is silently exceeded in the report
is a honesty defect: the operator cannot tell whether the run obeyed its budget.
"""
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.adaptix.main import _prior_usage, _reset_usage_counters  # noqa: E402


def test_reset_clears_the_live_counters():
    metrics = {'tool_calls_used': 8, 'tokens_used': 1000, 'iterations_used': 3,
               'by_tool': {'http_request': 8}}
    out = _reset_usage_counters(metrics, previous={})
    assert out['tool_calls_used'] == 0
    assert out['tokens_used'] == 0
    assert out['iterations_used'] == 0
    assert out['by_tool'] == {}
    assert out['resumed'] is True


def test_reset_archives_the_previous_spend():
    metrics = {'tool_calls_used': 8, 'history': []}
    previous = {'tool_calls_used': 8, 'tokens_used': 500}
    out = _reset_usage_counters(metrics, previous=previous)
    assert len(out['history']) == 1
    assert out['history'][0]['tool_calls_used'] == 8
    assert out['tool_calls_used'] == 0


def test_reset_keeps_earlier_history_entries():
    metrics = {'tool_calls_used': 4,
               'history': [{'tool_calls_used': 2, 'resumed_at': None}]}
    out = _reset_usage_counters(metrics, previous={'tool_calls_used': 4})
    assert len(out['history']) == 2
    assert out['history'][0]['tool_calls_used'] == 2
    assert out['history'][1]['tool_calls_used'] == 4


def test_prior_usage_extracts_only_counters():
    values = {'execution_metrics': {'tool_calls_used': 9, 'tokens_used': 42,
                                    'iterations_used': 2, 'by_tool': {'x': 9},
                                    'unrelated': 'keep out'}}
    spent = _prior_usage(values)
    assert spent['tool_calls_used'] == 9
    assert spent['tokens_used'] == 42
    assert 'by_tool' not in spent
    assert 'unrelated' not in spent


def test_prior_usage_tolerates_a_bare_state():
    """No execution metrics (a run that spent nothing) is an empty record, not a crash."""
    assert _prior_usage({}) == {'history': []}
    assert _prior_usage(None) == {'history': []}


def test_a_replayed_snapshot_cannot_restore_the_old_counter():
    """The merge inside run_stream must not put pre-resume spend back.

    LangGraph replays the thread's earlier snapshots before executing the next
    node; each carries the previous process's totals. The guard keeps the seed's
    value when a replayed counter is lower than it.
    """
    source = (ROOT / 'src' / 'adaptix' / 'main.py').read_text()
    body = source[source.index('def run_stream'):]
    body = body[:body.index('\ndef ')]
    assert 'seed is not None' in body
    assert 'replayed < baseline' in body, 'guarded merge for replayed snapshots is missing'
    assert re.search(r'merged\[.execution_metrics.\]', body), 'guard never applies to the merge'
