"""A port named in the target must survive into scope.

The defect: `127.0.0.1:3000` was normalized to `127.0.0.1`, the port validated and
then discarded, and ports came from policy alone (default 80,443). A fresh session
therefore probed :80 where nothing listened, recorded `origin_unreachable`, found no
routes, planned nothing, and stopped with `no_new_actions` in 32s -- while the target
was serving on :3000 the whole time.

The rule locked here: a port the operator names is authorisation scope. It is
preserved verbatim, added to scope, and never silently replaced by a default.
"""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.adaptix.security.scope import normalize_requests, scope_ports

POLICY = {'limits': {'allowed_ports': '80,443'}}


def test_a_bare_host_port_keeps_its_port():
    assert normalize_requests(['127.0.0.1:3000']) == ['127.0.0.1:3000']


def test_a_scheme_url_also_keeps_its_port():
    assert normalize_requests(['http://127.0.0.1:3000']) == ['127.0.0.1:3000']


def test_a_default_port_is_not_materialized():
    """No port named means no port invented."""
    assert normalize_requests(['127.0.0.1']) == ['127.0.0.1']
    assert normalize_requests(['http://127.0.0.1']) == ['127.0.0.1']


def test_the_named_port_enters_scope():
    ports = scope_ports(['127.0.0.1:3000'], POLICY)
    assert 3000 in ports, 'a port named in the target was left out of scope'


def test_the_defaults_are_still_present():
    """Naming a port adds to policy ports; it does not replace them."""
    ports = scope_ports(['127.0.0.1:3000'], POLICY)
    assert 80 in ports and 443 in ports


def test_a_scheme_url_contributes_its_port_too():
    assert 3000 in scope_ports(['http://127.0.0.1:3000'], POLICY)


def test_an_out_of_range_port_is_still_rejected():
    with pytest.raises(ValueError):
        normalize_requests(['127.0.0.1:99999'])


def test_a_plain_host_does_not_gain_a_port():
    assert scope_ports(['127.0.0.1'], POLICY) == [80, 443]


# --- resolve_scope must separate the host from its port ---------------------
# Preserving the port exposed a second defect: `127.0.0.1:3000` was handed to
# `ipaddress.ip_address` and then to DNS, failing with "Gagal DNS untuk
# 127.0.0.1:3000". The host is what gets resolved; the port is scope metadata.

POLICY = {'limits': {'allowed_ports': '80,443'}, 'allowed_cidrs': ['127.0.0.0/8'],
          'allowed_domains': [], 'blocked_cidrs': []}


def test_a_host_with_a_port_resolves_as_its_host():
    from src.adaptix.security.scope import resolve_scope
    manifest = resolve_scope(['127.0.0.1:3000'], POLICY)
    assert manifest['hosts'] == ['127.0.0.1']


def test_the_unit_keeps_the_operator_wording():
    from src.adaptix.security.scope import resolve_scope
    manifest = resolve_scope(['127.0.0.1:3000'], POLICY)
    assert manifest['units'][0].startswith('127.0.0.1')


def test_a_loopback_target_with_a_port_still_authorizes():
    """The reported command must not fail scope authorization."""
    from src.adaptix.security.scope import resolve_scope
    manifest = resolve_scope(['127.0.0.1:3000'], POLICY)
    assert manifest['hosts'] and 3000 in scope_ports(['127.0.0.1:3000'], POLICY)


# --- address classes must not be confused with host:port -------------------
# Preserving the port introduced a second round of defects, all caught by the
# existing suite: `urlsplit` misreads IPv6 (`//2001:db8::10`.hostname == '2001'),
# treats a CIDR mask as a URL path, and raises on `2001:db8::/64` claiming the port
# is 'db8::'. Each is locked here so the fix cannot silently regress.

def test_a_bare_ipv6_address_is_not_truncated():
    from src.adaptix.security.scope import resolve_scope
    manifest = resolve_scope(['192.0.2.0/30', '2001:db8::10'], POLICY)
    assert manifest['hosts'] == ['2001:db8::10'], 'IPv6 was truncated'


def test_a_cidr_keeps_its_mask():
    from src.adaptix.security.scope import resolve_scope
    manifest = resolve_scope(['10.0.0.0/8'], POLICY)
    assert manifest['networks'] == ['10.0.0.0/8']


def test_an_ipv6_cidr_keeps_its_mask():
    from src.adaptix.security.scope import resolve_scope
    manifest = resolve_scope(['2001:db8::/64'], POLICY)
    assert manifest['networks'] == ['2001:db8::/64']


def test_an_ipv6_cidr_does_not_raise_on_its_colons():
    """`urlsplit('//2001:db8::/64').port` raises claiming the port is 'db8::'."""
    assert scope_ports(['2001:db8::/64'], POLICY) == [80, 443]


def test_a_cidr_contributes_no_port():
    assert scope_ports(['10.0.0.0/8'], POLICY) == [80, 443]


def test_a_bare_ipv6_contributes_no_port():
    assert scope_ports(['2001:db8::10'], POLICY) == [80, 443]


def test_a_bracketed_ipv6_port_is_read():
    assert 8443 in scope_ports(['[2001:db8::10]:8443'], POLICY)
