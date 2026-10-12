from src.adaptix.agents.reflector import reflection_verification


def test_verified_when_severity_and_http_evidence_match():
    state = {
        'candidates': [{'template_id': 'critical-rce', 'url': 'http://127.0.0.1:18080/', 'severity': 'high', 'status': 'candidate_unverified'}],
        'http_services': [{'url': 'http://127.0.0.1:18080/', 'status_code': 200, 'title': 'Lab'}],
    }
    result = reflection_verification(state)
    assert len(result['verified_findings']) == 1
    assert result['verified_findings'][0]['verification_status'] == 'verified'
    assert result['rejected_findings'] == []
    assert result['stop_reason'] is None


def test_info_severity_rejected_not_verified():
    state = {
        'candidates': [{'template_id': 'adaptix-http-baseline', 'url': 'http://127.0.0.1:18080/', 'severity': 'info', 'status': 'candidate_unverified'}],
        'http_services': [{'url': 'http://127.0.0.1:18080/', 'status_code': 200, 'title': 'Lab'}],
    }
    result = reflection_verification(state)
    assert result['verified_findings'] == []
    assert len(result['rejected_findings']) == 1
    assert result['rejected_findings'][0]['verification_status'] == 'rejected'


def test_no_http_match_is_inconclusive():
    state = {
        'candidates': [{'template_id': 'x', 'url': 'http://127.0.0.1:9999/', 'severity': 'high', 'status': 'candidate_unverified'}],
        'http_services': [],
    }
    result = reflection_verification(state)
    assert result['verified_findings'] == []
    assert len(result['inconclusive_findings']) == 1


def test_stop_reason_set_when_all_candidates_fail_verification():
    state = {
        'candidates': [{'template_id': 'x', 'url': 'http://127.0.0.1:9999/', 'severity': 'info', 'status': 'candidate_unverified'}],
        'http_services': [],
    }
    result = reflection_verification(state)
    assert result['stop_reason'] == 'all_candidates_rejected_or_inconclusive'
