"""Regression checks for retirement, bounded scope and evidence-only AI output."""
import pytest

from src.adaptix.config import config
from src.adaptix.security.ports import ports_for_state
from src.adaptix.security.scope import scope_ports
from src.adaptix.tools import nmap, registry
from work.recon_local import load_words, validate_assessment


def test_retired_capability_cannot_be_reenabled_by_old_config(monkeypatch):
    original = registry.config
    monkeypatch.setattr(registry, 'config', lambda name: {
        **original(name), 'tools': {**original(name)['tools'],
                                  'nmap': {'enabled': True, 'command': 'nmap'}}})
    monkeypatch.setenv('ADAPTIX_NMAP_PATH', '/usr/bin/nmap')
    catalog = registry.tool_registry()
    assert catalog['nmap']['enabled'] is False
    assert catalog['nmap']['path'] is None
    assert 'nmap' not in registry.tool_handlers()


def test_nmap_cannot_launch_process_even_when_imported_directly(monkeypatch):
    monkeypatch.setattr(registry.subprocess, 'run', lambda *a, **kw: pytest.fail('Unexpected process'))
    state = {'hosts': ['127.0.0.1'], 'services': [{'port': 80}], 'events': []}
    result = nmap.reconnaissance(state)
    assert set(result) == {'events'}
    assert state['services'] == [{'port': 80}]


def test_default_http_ports_are_bounded_and_explicit_url_adds_port():
    policy = config('scope.yaml')
    ports = ports_for_state({}, policy['limits'])
    assert 22 not in ports and 65535 not in ports
    assert ports == [80, 443, 3000, 5000, 8000, 8080, 8081, 8443, 9443, 18080]
    assert 18080 in scope_ports(['http://127.0.0.1:18080'], policy)


def test_retired_nmap_all_setting_cannot_expand_web_port_scope():
    assert ports_for_state({}, {'nmap_ports': 'all'}) == [80, 443]


def test_combining_policy_lists_cannot_exceed_explicit_port_limit():
    with pytest.raises(ValueError):
        ports_for_state({}, {'allowed_ports': list(range(10000, 10020)),
                             'web_ports': list(range(11000, 11020))})


def test_seclists_subset_has_verified_provenance():
    assert len(load_words()) == 8


def test_model_evidence_accepts_real_statuses():
    value = {'endpoints': [{'path': '/api', 'status': 200, 'classification': 'content'}],
             'observed_count': 1, 'verified_vulnerabilities': 0}
    assert validate_assessment(value, [{'path': '/api', 'status': 200}]) == value


@pytest.mark.parametrize('endpoints,count,verified', [
    ([{'path': '/admin', 'status': 200, 'classification': 'content'}], 1, 0),
    ([], 1, 0),
    ([], 0, 1),
])
def test_empty_evidence_rejects_invented_endpoints_counts_and_findings(endpoints, count, verified):
    with pytest.raises(ValueError):
        validate_assessment({'endpoints': endpoints, 'observed_count': count,
                             'verified_vulnerabilities': verified}, [])


def test_duplicate_evidence_cannot_inflate_model_results():
    row = {'path': '/api', 'status': 200, 'classification': 'content'}
    with pytest.raises(ValueError):
        validate_assessment({'endpoints': [row, row], 'observed_count': 1,
                             'verified_vulnerabilities': 0}, [{'path': '/api', 'status': 200}])


def test_provider_secret_is_absent_from_checkpoints_and_nested_evidence(tmp_path, monkeypatch):
    import json
    from pathlib import Path
    from src.adaptix.evidence import audit, storage
    from src.adaptix.evidence.sanitize import sanitize, scenario_secrets
    monkeypatch.setattr(storage, 'ROOT', tmp_path)
    secret = 'SYNTHETIC_AUDIT_MARKER_2026'
    state = {'run_id': 'redaction-check', 'run_started_at': 1, 'llm_api_key': secret,
             'errors': ['Provider echoed ' + secret]}
    data = json.loads(Path(audit.checkpoint(state)).read_text())
    assert 'llm_api_key' not in data
    assert secret not in json.dumps(data)
    assert sanitize({'nested': {'llm_api_key': secret}})['nested']['llm_api_key'] == '[REDACTED]'
    assert secret not in sanitize('Provider echoed ' + secret, scenario_secrets(state))
