"""A verified finding must reach the planner, or "escalate on what you found" is a claim.

Measured defect: the planner payload carried `idor_findings` only. A verified SQL
injection or DOM XSS never entered the prompt, so no decision could ever escalate on it.
"""
import json

from src.adaptix.agents.finding_context import (CLASS_ESCALATIONS, escalation_block,
                                                verified_findings)
from src.adaptix.agents.context import ESSENTIAL_FIELDS


def _state(**overrides):
    state = {
        'idor_findings': [{'target': 'http://127.0.0.1:3000/rest/basket/8', 'object_id': '8',
                           'severity': 'high', 'verification_status': 'verified',
                           'verification_basis': 'private_object_access',
                           'verification_evidence': {'evidence_ref': '/a/idor.json'}}],
        'injection_findings': [{'target': 'http://127.0.0.1:3000/rest/products/search?q=x',
                                'parameter': 'q', 'payload': "a' OR 1=1--",
                                'verification_status': 'verified',
                                'verification_basis': 'differential_injection'}],
        'script_findings': [{'target': 'http://127.0.0.1:3000/#/search?q=m', 'marker': 'axm1',
                             'verification_status': 'verified'}],
    }
    state.update(overrides)
    return state


def test_every_verified_class_reaches_the_planner():
    classes = {row['class'] for row in verified_findings(_state())}
    assert classes == {'broken_object_level_authorization', 'sql_injection',
                       'cross_site_scripting'}


def test_a_rejected_finding_is_not_a_lead():
    state = _state()
    state['injection_findings'][0]['verification_status'] = 'rejected'
    classes = {row['class'] for row in verified_findings(state)}
    assert 'sql_injection' not in classes


def test_a_refuted_result_is_not_a_lead():
    state = _state()
    state['injection_findings'][0]['result'] = 'refuted'
    assert 'sql_injection' not in {row['class'] for row in verified_findings(state)}


def test_each_finding_carries_concrete_escalation_options():
    for row in verified_findings(_state()):
        assert row['escalation_options'], row['class']
        assert all(isinstance(option, str) and option for option in row['escalation_options'])
        assert len(row['escalation_options']) <= 3


def test_the_same_endpoint_is_not_listed_twice():
    state = _state()
    state['injection_findings'].append(dict(state['injection_findings'][0]))
    rows = [row for row in verified_findings(state) if row['class'] == 'sql_injection']
    assert len(rows) == 1


def test_findings_are_bounded():
    state = {'injection_findings': [{'target': 'http://h/p?q=%d' % i, 'parameter': 'q',
                                     'verification_status': 'verified'} for i in range(40)]}
    assert len(verified_findings(state)) <= 6


def test_block_is_absent_when_nothing_is_verified():
    assert escalation_block({}) == {}
    assert escalation_block({'injection_findings': [
        {'target': 'x', 'verification_status': 'rejected'}]}) == {}


def test_block_states_the_escalation_rule():
    block = escalation_block(_state())
    policy = block['finding_escalation_policy']
    assert 'SAME target' in policy
    # The rule must require an escalation action, not merely discourage repetition:
    # the softer wording was measured to yield actions=[] on a verified finding.
    assert 'requires one more action' in policy
    assert 'Do not re-send the payload' in policy


def test_the_trigger_survives_compaction():
    """Compaction must never strip the block, or the trigger disappears under pressure."""
    assert 'verified_findings' in ESSENTIAL_FIELDS
    assert 'finding_escalation_policy' in ESSENTIAL_FIELDS


def test_escalation_options_exist_for_every_supported_class():
    for key, options in CLASS_ESCALATIONS.items():
        assert options, key
