"""A verified finding must carry its signed evidence, and fenced JSON must still parse.

Both defects were measured on one real 26k-token planner call:
  * a complete, valid decision inside a ```json fence was discarded as `json_invalid`;
  * SQLi and XSS rows reached the planner with an empty `evidence_ref` although the run
    held a sealed record for each, so the model judged them unproven and declined to
    escalate.
"""
import json

from src.adaptix.agents.finding_context import verified_findings
from src.adaptix.agents.schema import strip_code_fence

URL = 'http://127.0.0.1:3000/rest/products/search?q=a%27+OR+1%3D1--'


def test_a_fenced_decision_is_unwrapped():
    body = '{"actions":[],"rationale":"x"}'
    assert strip_code_fence('```json\n' + body + '\n```') == body


def test_a_fence_without_a_language_tag_is_unwrapped():
    body = '{"actions":[]}'
    assert strip_code_fence('```\n' + body + '\n```') == body


def test_plain_json_is_untouched():
    body = '{"actions":[]}'
    assert strip_code_fence(body) == body
    assert strip_code_fence('  ' + body + '  ') == body


def test_an_unterminated_fence_still_yields_the_body():
    body = '{"actions":[]'
    assert strip_code_fence('```json\n' + body) == body


def test_text_that_is_not_json_is_returned_as_is():
    """Stripping must never invent a body from prose."""
    assert strip_code_fence('I could not decide.') == 'I could not decide.'


def _state():
    return {
        'injection_findings': [{'target': URL, 'parameter': 'q', 'payload': "a' OR 1=1--",
                                'verification_status': 'verified',
                                'verification_basis': 'differential_injection'}],
        'script_findings': [{'target': 'http://127.0.0.1:3000/#/search?q=m', 'marker': 'axm1',
                             'verification_status': 'verified'}],
        'verification_evidence': [
            {'url': URL, 'result': 'confirmed',
             'evidence_ref': '/runs/v/verification-sqli.json'},
            {'url': 'http://127.0.0.1:3000/#/search?q=m', 'result': 'confirmed',
             'evidence_ref': '/runs/v/verification-xss.json'},
        ],
    }


def test_a_finding_without_its_own_ref_inherits_the_sealed_one():
    rows = {row['class']: row for row in verified_findings(_state())}
    assert rows['sql_injection']['evidence_ref'] == '/runs/v/verification-sqli.json'
    assert rows['cross_site_scripting']['evidence_ref'] == '/runs/v/verification-xss.json'


def test_an_explicit_ref_wins_over_the_sealed_index():
    state = _state()
    state['injection_findings'][0]['evidence_ref'] = '/own/ref.json'
    rows = {row['class']: row for row in verified_findings(state)}
    assert rows['sql_injection']['evidence_ref'] == '/own/ref.json'


def test_no_ref_is_invented_when_none_is_sealed():
    state = _state()
    state['verification_evidence'] = []
    rows = {row['class']: row for row in verified_findings(state)}
    assert rows['sql_injection']['evidence_ref'] == ''


def test_a_sealed_record_for_another_path_is_not_borrowed():
    """A ref for a different endpoint would misattribute the proof."""
    state = _state()
    state['verification_evidence'] = [{'url': 'http://127.0.0.1:3000/rest/basket/8',
                                       'result': 'confirmed',
                                       'evidence_ref': '/runs/v/other.json'}]
    rows = {row['class']: row for row in verified_findings(state)}
    assert rows['sql_injection']['evidence_ref'] == ''
