import json
import time
import pytest
from src.adaptix.security import authorization, scope as core
from src.adaptix.workflow import nodes
from src.adaptix.config import config


@pytest.fixture
def keytmp(tmp_path, monkeypatch):
    monkeypatch.setattr(authorization, 'KEY_PATH', tmp_path / 'key')
    authorization._key(create=True)
    return tmp_path


def test_remote_requires_signed_grant(monkeypatch):
    result = nodes.scope_guard({'target': ['192.0.2.10'], 'authorization_confirmed': True})
    assert result['status'] == 'scope_blocked'
    assert 'signed grant' in result['errors'][0]


def test_approved_remote_grant_no_yaml_edit(keytmp):
    path, _ = authorization.issue_grant(['192.0.2.10'], 'alice', destination=keytmp/'grant.json')
    state = {'target': ['192.0.2.10'], 'authorization_confirmed': True,
             'principal': 'alice', 'grant': str(path)}
    result = nodes.scope_guard(state)
    assert result['status'] == 'scope_ok'
    assert result['hosts'] == ['192.0.2.10']
    assert result['authorization']['type'] == 'signed_grant'


def test_unsigned_tamper_refused(keytmp):
    path, _ = authorization.issue_grant(['192.0.2.10'], 'alice', destination=keytmp/'grant.json')
    record = json.loads(path.read_text())
    record['payload']['hosts'].append('198.51.100.2')
    path.write_text(json.dumps(record))
    with pytest.raises(ValueError, match='signature'):
        authorization.verify_grant(path, ['192.0.2.10'], 'alice', config('scope.yaml'))


def test_principal_or_target_mismatch(keytmp):
    path, _ = authorization.issue_grant(['192.0.2.10'], 'alice', destination=keytmp/'grant.json')
    with pytest.raises(ValueError, match='principal'):
        authorization.verify_grant(path, ['192.0.2.10'], 'bob', config('scope.yaml'))
    with pytest.raises(ValueError, match='di luar grant'):
        authorization.verify_grant(path, ['192.0.2.11'], 'alice', config('scope.yaml'))


def test_expired_grant_refused(keytmp, monkeypatch):
    path, _ = authorization.issue_grant(['192.0.2.10'], 'alice', destination=keytmp/'grant.json')
    now = time.time()
    monkeypatch.setattr(authorization.time, 'time', lambda: now + 172800)
    with pytest.raises(ValueError, match='kadaluarsa'):
        authorization.verify_grant(path, ['192.0.2.10'], 'alice', config('scope.yaml'))


def test_dynamic_dns_is_pinned_and_change_refused(keytmp, monkeypatch):
    addresses = ['192.0.2.22']
    def fake_lookup(host, port, type):
        assert host == 'lab.example'
        return [(None, None, None, None, (addresses[0], 0))]
    monkeypatch.setattr(core.socket, 'getaddrinfo', fake_lookup)
    path, _ = authorization.issue_grant(['lab.example'], 'alice', destination=keytmp/'grant.json')
    assert authorization.verify_grant(path, ['lab.example'], 'alice', config('scope.yaml'))[0] == ['192.0.2.22']
    addresses[0] = '192.0.2.99'
    with pytest.raises(ValueError, match='DNS'):
        authorization.verify_grant(path, ['lab.example'], 'alice', config('scope.yaml'))


def test_global_blocklist_applies_to_dynamic_grants(keytmp):
    with pytest.raises(ValueError, match='IP'):
        authorization.issue_grant(['169.254.169.254'], 'alice', destination=keytmp/'grant.json')
