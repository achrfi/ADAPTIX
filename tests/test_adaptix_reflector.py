"""Regressions: a reachable HTTP service is not proof of RCE, IDOR or other vulnerabilities."""
from src.adaptix.agents.reflector import reflection_verification


def _result(severity='high', http_status=200, template='critical-rce', evidence=None):
    state = {'candidates': [{'template_id': template, 'url': 'http://127.0.0.1:18080/',
                             'severity': severity, 'status': 'candidate_unverified'}],
             'http_services': [{'url': 'http://127.0.0.1:18080', 'status_code': http_status,
                                'title': 'Lab'}],
             'verification_evidence': evidence or []}
    return reflection_verification(state)


def test_200_does_not_verify_rce():
    result = _result()
    assert not result['verified_findings']
    assert not result['rejected_findings']
    assert result['inconclusive_findings'][0]['actual_observation']['status_code'] == 200


def test_low_severity_not_rejected_without_proof():
    result = _result(severity='low')
    assert result['inconclusive_findings'] and not result['rejected_findings']


def test_403_does_not_reject_idor():
    result = _result(http_status=403, template='idor')
    assert result['inconclusive_findings'] and not result['rejected_findings']


def test_missing_http_is_inconclusive():
    result = reflection_verification({'candidates': [
        {'template_id': 'x', 'url': 'http://127.0.0.1:9999/', 'severity': 'high'}]})
    assert len(result['inconclusive_findings']) == 1


def test_baseline_is_not_vulnerability():
    result = _result(severity='info', template='adaptix-http-baseline')
    assert not result['verified_findings']
    assert len(result['rejected_findings']) == 1


def test_explicit_vulnerability_specific_confirmation():
    proof = [{'template_id': 'idor', 'url': 'http://127.0.0.1:18080',
              'verification_method': 'deterministic_replay',
              'evidence_ref': 'artifacts/replay/evidence.json', 'result': 'confirmed'}]
    result = _result(template='idor', evidence=proof)
    assert len(result['verified_findings']) == 1


def test_unsubstantiated_confirmation_does_not_verify():
    proof = [{'template_id': 'idor', 'url': 'http://127.0.0.1:18080', 'result': 'confirmed'}]
    result = _result(template='idor', evidence=proof)
    assert len(result['inconclusive_findings']) == 1
