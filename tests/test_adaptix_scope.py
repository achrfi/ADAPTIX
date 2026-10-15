import pytest
from src.adaptix.security.scope import expand_targets, allowed_url, resolve_scope, scope_window
from src.adaptix.workflow.nodes import scope_guard

SETTINGS = {'allowed_cidrs': ['127.0.0.0/8', '192.168.56.0/28'],
            'allowed_domains': ['localhost'], 'limits': {'max_hosts': 16}}


def test_allow_local_and_explicit_private_ip():
    assert expand_targets(['127.0.0.1', '192.168.56.10'], SETTINGS) == ['127.0.0.1', '192.168.56.10']


def test_reject_outside_scope():
    with pytest.raises(ValueError, match='allowlist'):
        expand_targets(['8.8.8.8'], SETTINGS)


def test_cidr_expansion():
    assert expand_targets(['192.168.56.0/30'], SETTINGS) == ['192.168.56.1', '192.168.56.2']


def test_large_cidr_remains_compact_and_has_budget_sized_window():
    scope = resolve_scope(['127.0.0.0/8'], SETTINGS, require_allowlist=True)
    assert scope['total_units'] == 16777214
    assert scope['networks'] == ['127.0.0.0/8']
    assert scope_window(scope, [], 2) == ['127.0.0.1', '127.0.0.2']


def test_loopback_scope_needs_no_redundant_confirmation_flag():
    response = scope_guard({'target': ['127.0.0.1'], 'events': [], 'authorization_confirmed': False})
    assert response['status'] == 'scope_ok'


def test_external_url_and_port_blocked():
    assert allowed_url('http://127.0.0.1:18080/', ['127.0.0.1'], {18080})
    assert not allowed_url('http://127.0.0.1:81/', ['127.0.0.1'], {18080})
    assert not allowed_url('http://8.8.8.8/', ['127.0.0.1'], {80})
