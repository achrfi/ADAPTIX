"""A verified finding must trigger an escalation decision, not just a citation.

Measured end to end against the real gateway. With one verified SQL injection on `q` and
an objective asking for impact, the planner returned `http_request` against the SAME
parameter with a UNION payload — the behaviour the escalation block exists to produce.
Before it, the planner could not see a SQL finding at all (only `idor_findings` reached
the prompt), so no such decision was reachable.
"""
import json

from src.adaptix.agents.finding_context import (CLASS_ESCALATIONS, escalation_block,
                                                verified_findings)

BASE_STATE = {
    'injection_findings': [{'target': 'http://h/rest/products/search?q=a',
                            'parameter': 'q', 'payload': "a' OR 1=1--",
                            'verification_status': 'verified',
                            'verification_basis': 'differential_injection'}],
    'verification_evidence': [{'url': 'http://h/rest/products/search?q=a',
                               'result': 'confirmed',
                               'evidence_ref': '/runs/v/sqli.json'}],
}


def test_a_verified_sqli_is_visible_with_its_target_and_parameter():
    rows = verified_findings(BASE_STATE)
    assert len(rows) == 1
    row = rows[0]
    assert row['class'] == 'sql_injection'
    assert row['parameter'] == 'q'
    assert row['evidence_ref'] == '/runs/v/sqli.json'


def test_the_sqli_escalation_options_name_the_deterministic_capability():
    """Measured: a hand-written UNION needs the column count, and a wrong guess fails.

    The menu must name the capability that measures it rather than only the technique,
    so the model is not invited to author a payload whose column count it has to guess.
    """
    options = ' '.join(CLASS_ESCALATIONS['sql_injection']).lower()
    assert 'union_extract' in options
    assert 'union' in options
    assert 'blind' in options


def test_the_block_pins_the_escalation_to_the_same_target_and_parameter():
    policy = escalation_block(BASE_STATE)['finding_escalation_policy']
    assert 'SAME target and parameter' in policy
    # The policy must name the capability for the class it is describing.
    assert 'union_extract' in policy


def test_the_payload_names_the_verified_class_and_its_options():
    """The model needs the class and the menu together, or it cannot pick an escalation."""
    block = escalation_block(BASE_STATE)
    row = block['verified_findings'][0]
    assert row['class'] == 'sql_injection'
    assert row['escalation_options']
    # Round-trips as JSON: it travels inside the planner prompt.
    assert json.loads(json.dumps(block))['verified_findings'][0]['class'] == 'sql_injection'


def test_an_unverified_lead_cannot_trigger_an_escalation():
    state = {'injection_findings': [{'target': 'http://h/p?q=a', 'parameter': 'q',
                                     'verification_status': 'inconclusive'}]}
    assert escalation_block(state) == {}
