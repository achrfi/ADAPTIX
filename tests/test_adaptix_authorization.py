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


def test_cli_issues_domain_grant_without_confirmation_flag(keytmp, monkeypatch):
    monkeypatch.setattr(core.socket, 'getaddrinfo', lambda *a, **kw: [(None,None,None,None,('192.0.2.22',0))])
    # Keep auto-issued test grants in the test directory.
    real_issue = authorization.issue_grant
    monkeypatch.setattr(authorization, 'issue_grant', lambda targets, principal, hours: real_issue(targets, principal, hours, keytmp/'auto.json'))
    grant, principal = authorization.authorize_cli_targets(['https://lab.example:9443/start'], 'operator')
    state = {'target':['https://lab.example:9443/start'], 'grant':grant, 'principal':principal}
    result = nodes.scope_guard(state)
    assert result['status'] == 'scope_ok'
    assert result['scope_aliases'] == {'lab.example':['192.0.2.22']}
    assert 9443 in result['scope_ports']
    assert core.allowed_url('https://lab.example:9443/next', result['hosts'], result['scope_ports'], result['scope_aliases'])
    assert not core.allowed_url('https://other.example:9443/', result['hosts'], result['scope_ports'], result['scope_aliases'])


def test_domain_dns_change_blocks_execution_before_adapter(keytmp, monkeypatch):
    address = ['192.0.2.22']
    monkeypatch.setattr(core.socket, 'getaddrinfo', lambda *a, **kw: [(None,None,None,None,(address[0],0))])
    grant,_ = authorization.issue_grant(['lab.example'], 'operator', destination=keytmp/'domain.json')
    state = {'target':['lab.example'], 'grant':str(grant), 'principal':'operator'}
    state.update(nodes.scope_guard(state))
    state['planned_actions'] = [{'tool':'httpx','target':'https://lab.example/','reason':'probe'}]
    address[0] = '192.0.2.99'
    result = nodes.execute_action(state)
    assert result['stop_reason'] == 'authorization_invalid'
    assert 'execution_metrics' not in result


def test_cidr_and_ipv6_grants_work_without_confirmation_flag(keytmp):
    grant,_ = authorization.issue_grant(['192.0.2.0/30','2001:db8::10'], 'operator', destination=keytmp/'ranges.json')
    result = nodes.scope_guard({'target':['192.0.2.0/30','2001:db8::10'], 'grant':str(grant), 'principal':'operator'})
    assert result['status'] == 'scope_ok'
    assert set(result['hosts']) == {'192.0.2.1','192.0.2.2','2001:db8::10'}


def test_v2_large_cidr_grant_is_compact_and_signed(keytmp):
    path,payload=authorization.issue_grant(['10.0.0.0/8','2001:db8::/64'],'operator',destination=keytmp/'large.json')
    assert payload['version']==2 and payload['hosts']==[]
    assert path.stat().st_size<1500
    manifest,_=authorization.verify_scope_grant(path,['10.0.0.0/8','2001:db8::/64'],'operator',config('scope.yaml'))
    assert manifest['total_units']>2**63
    result=nodes.scope_guard({'target':['10.0.0.0/8','2001:db8::/64'],'grant':str(path),'principal':'operator','tool_call_budget':2})
    assert result['status']=='scope_ok'
    assert result['hosts']==['10.0.0.1','10.0.0.2']


def test_legacy_v1_grant_remains_valid(keytmp):
    import hashlib,hmac
    now=int(time.time())
    payload={'version':1,'grant_id':'legacy','principal':'operator','targets':['192.0.2.0/30'],
      'hosts':['192.0.2.1','192.0.2.2'],'issued_at':now,'expires_at':now+3600}
    record={'payload':payload,'signature':hmac.new(authorization._key(),authorization._payload_bytes(payload),hashlib.sha256).hexdigest()}
    path=keytmp/'v1.json'; path.write_text(json.dumps(record))
    manifest,grant_id=authorization.verify_scope_grant(path,['192.0.2.0/30'],'operator',config('scope.yaml'))
    assert grant_id=='legacy' and manifest['networks']==['192.0.2.0/30']
