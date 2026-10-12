import pytest
from src.adaptix.security.scope import expand_targets, allowed_url
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


def test_large_cidr_refused():
    with pytest.raises(ValueError, match='CIDR terlalu besar'):
        expand_targets(['127.0.0.0/8'], SETTINGS)


def test_no_authorization_blocks():
    response = scope_guard({'target': ['127.0.0.1'], 'events': [], 'authorization_confirmed': False})
    assert response['status'] == 'scope_blocked'


def test_external_url_and_port_blocked():
    assert allowed_url('http://127.0.0.1:18080/', ['127.0.0.1'], {18080})
    assert not allowed_url('http://127.0.0.1:81/', ['127.0.0.1'], {18080})
    assert not allowed_url('http://8.8.8.8/', ['127.0.0.1'], {80})
