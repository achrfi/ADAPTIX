from src.adaptix.tools import idor as idor_module


class _FakeResponse:
    def __init__(self, status_code, text):
        self.status_code = status_code
        self.text = text


class _FakeClient:
    def __init__(self, responses):
        self._responses = responses

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

<<<<<<< HEAD
    def request(self, method, url, headers=None, **kwargs):
=======
    def request(self, method, url, headers=None):
>>>>>>> origin/main
        return self._responses.pop(0)


def _scenario():
    return {
        'name': 'order-access', 'base_url': 'http://127.0.0.1:8080',
        'path_template': '/api/orders/{object_id}', 'object_id': '42',
        'owner_identity': {'name': 'userA', 'headers': {'Authorization': 'Bearer a'}},
        'other_identity': {'name': 'userB', 'headers': {'Authorization': 'Bearer b'}},
        'method': 'GET',
<<<<<<< HEAD
        'ground_truth': {'private': True, 'identities_valid': True, 'owner': 'userA', 'object_id': '42'},
=======
>>>>>>> origin/main
    }


def test_confirmed_idor_when_other_identity_gets_identical_response(monkeypatch):
    responses = [_FakeResponse(200, '{"id":42}'), _FakeResponse(200, '{"id":42}')]
    monkeypatch.setattr(idor_module.httpx_lib, 'Client', lambda **kw: _FakeClient(responses))
    state = {'hosts': ['127.0.0.1'], 'idor_scenarios': [_scenario()]}
    result = idor_module.idor_test(state)
    assert len(result['idor_findings']) == 1
    assert result['idor_findings'][0]['verification_status'] == 'verified'


def test_rejected_when_authorization_enforced(monkeypatch):
    responses = [_FakeResponse(200, '{"id":42}'), _FakeResponse(403, 'forbidden')]
    monkeypatch.setattr(idor_module.httpx_lib, 'Client', lambda **kw: _FakeClient(responses))
    state = {'hosts': ['127.0.0.1'], 'idor_scenarios': [_scenario()]}
    result = idor_module.idor_test(state)
    assert result['idor_findings'][0]['verification_status'] == 'rejected'


def test_scenario_outside_scope_skipped_with_error():
    state = {'hosts': ['127.0.0.1'], 'idor_scenarios': [dict(_scenario(), base_url='http://evil.example.com')]}
    result = idor_module.idor_test(state)
    assert result['idor_findings'] == []
    assert any('not in authorized hosts' in e for e in result['errors'])


def test_no_scenarios_skips_cleanly():
    state = {'hosts': ['127.0.0.1']}
    result = idor_module.idor_test(state)
    assert result['idor_findings'] == []


def test_memoized_skip_when_already_run():
    state = {'hosts': ['127.0.0.1'], 'idor_findings': [{'already': 'done'}]}
    result = idor_module.idor_test(state)
    assert 'idor_findings' not in result
