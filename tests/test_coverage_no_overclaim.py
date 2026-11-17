"""Coverage must not claim a class as `tested` when no probe can test it.

Measured defect: `TOOL_CLASSES['injection_probe']` mapped to both `sql_injection`
and `nosql_injection`, while the probe sends only boolean SQL predicates. A run that
executed one SQLi probe therefore reported `nosql_injection: tested` - a false
statement about a class nothing had exercised. A false `tested` is the one failure
mode `coverage.py` exists to prevent, so it is pinned from three directions: the
mapping must not over-claim, the payload family must actually exist before the class
can be claimed again, and the reason string must not imply the tool could have acted.
"""
import pathlib
import sys

import pytest

from src.adaptix.reporting import coverage
from src.adaptix.reporting.coverage import NOT_TESTED, TESTED, TOOL_CLASSES


def _probe_source_text():
    """Every tool module's source, used to prove a payload family exists at all."""
    tools_dir = pathlib.Path(coverage.__file__).resolve().parents[1] / 'tools'
    return '\n'.join(path.read_text(encoding='utf-8', errors='replace')
                     for path in sorted(tools_dir.glob('*.py')))


@pytest.fixture
def executed_probe_state():
    """A run that executed exactly one injection_probe action."""
    return {
        'action_outcomes': [{'action': {'tool': 'injection_probe',
                                        'target': 'http://127.0.0.1:3000/api/Cards?q=x'}}],
        'candidates': [], 'verified_findings': [], 'scanner_matched_findings': [],
        'inconclusive_findings': [], 'rejected_findings': [], 'findings': [], 'hypotheses': [],
        'verification_evidence': [],
    }


def test_injection_probe_claims_sql_and_not_nosql():
    assert 'sql_injection' in TOOL_CLASSES['injection_probe']
    assert 'nosql_injection' not in TOOL_CLASSES['injection_probe'], (
        'injection_probe sends boolean SQL predicates only; claiming NoSQL coverage '
        'from it reported a class as tested that no check had exercised')


def test_no_tool_claims_nosql_while_no_operator_payload_exists():
    """Guard rail for the next person: mapping the class again re-opens the defect."""
    claimants = {tool for tool, mapped in TOOL_CLASSES.items() if 'nosql_injection' in mapped}
    source = _probe_source_text()
    has_operator_payload = any(op in source for op in ('$ne', '$gt', '$regex', '$where'))
    if has_operator_payload:
        # A real probe now exists; the assertion in the test above still has to be
        # revisited deliberately rather than silently satisfied.
        return
    assert not claimants, (
        'no NoSQL operator payload exists in tools/ but '
        f'{sorted(claimants)} claim the class: add the probe, or remove the claim')


def test_nosql_is_not_reported_tested_after_a_sql_only_run(executed_probe_state):
    report = coverage.assessment_coverage(executed_probe_state)
    assert report['classes']['sql_injection']['status'] == TESTED
    assert report['classes']['nosql_injection']['status'] == NOT_TESTED


def test_untestable_class_reason_does_not_imply_a_missing_action(executed_probe_state):
    report = coverage.assessment_coverage(executed_probe_state)
    reason = report['classes']['nosql_injection']['reason']
    assert 'no probe reports this class' in reason
    assert 'executed no action' not in reason, (
        'saying no action ran implies the tool could have run one for this class')


def test_sql_class_is_still_reported_tested(executed_probe_state):
    """The fix must not over-correct into under-reporting the class that is tested."""
    report = coverage.assessment_coverage(executed_probe_state)
    assert report['classes']['sql_injection']['status'] == TESTED
    assert 'action(s) for this class executed' in report['classes']['sql_injection']['reason']
