"""Preserve logical hostname while connecting exclusively to a pinned IP."""
import ipaddress
from urllib.parse import urlsplit, urlunsplit
from src.adaptix.security.scope import canonical_host, allowed_url, endpoint_key
from src.adaptix.config import config
from src.adaptix.security.ports import ports_for_state


def bind_url(url, state):
    ports = ports_for_state(state, config('scope.yaml')['limits'])
    aliases = state.get('scope_aliases', {})
    if not allowed_url(url, state.get('hosts', []), ports, aliases, state.get('scope_networks')):
        raise ValueError('Endpoint outside pinned scope')
    parsed = urlsplit(url)
    host = canonical_host(parsed.hostname)
    if host not in aliases:
        return url, {}, None
    pins = aliases[host]
    pinned = sorted(pins, key=lambda x: (ipaddress.ip_address(x).version, int(ipaddress.ip_address(x))))[0]
    address = '[' + pinned + ']' if ':' in pinned else pinned
    netloc = address + (':' + str(parsed.port) if parsed.port else '')
    authority = host + (':' + str(parsed.port) if parsed.port else '')
    return urlunsplit((parsed.scheme, netloc, parsed.path, parsed.query, '')), {'Host': authority}, host


def bind_cli_urls(urls, state):
    bindings = [bind_url(url, state) for url in urls]
    identities = {(tuple(headers.items()), sni) for _, headers, sni in bindings}
    if len(identities) != 1:
        raise ValueError('Mixed virtual hosts require separate agent actions')
    flags = []
    if bindings:
        _, headers, sni = bindings[0]
        for key, value in headers.items():
            flags.extend(['-H', key + ': ' + value])
        if sni:
            flags.extend(['-sni', sni])
    return [entry[0] for entry in bindings], list(zip([entry[0] for entry in bindings], urls)), flags


def logical_url(url, bindings, allow_paths=False):
    for actual, logical in bindings:
        if endpoint_key(url) == endpoint_key(actual):
            return logical
        if allow_paths and endpoint_key(url) and endpoint_key(actual) and endpoint_key(url)[:3] == endpoint_key(actual)[:3]:
            matched, original = urlsplit(url), urlsplit(logical)
            return urlunsplit((original.scheme, original.netloc, matched.path, matched.query, matched.fragment))
    return url


def browser_resolver_rules(state):
    rules = []
    for name, pins in state.get('scope_aliases', {}).items():
        host = canonical_host(name)
        if not pins or not set(pins).issubset(set(state.get('hosts', []))):
            raise ValueError('Invalid browser DNS pins')
        pinned = sorted(pins, key=lambda x: (ipaddress.ip_address(x).version, int(ipaddress.ip_address(x))))[0]
        address = '[' + pinned + ']' if ':' in pinned else pinned
        rules.append('MAP ' + host + ' ' + address)
    # Chromium applies wildcard rules to IP literals too. Preserve only approved IPs.
    for value in sorted(set(state.get('hosts', []))):
        ip = ipaddress.ip_address(value)
        address = '[' + str(ip) + ']' if ip.version == 6 else str(ip)
        rules.append('MAP ' + address + ' ' + address)
    rules.append('MAP * ~NOTFOUND')
    return ', '.join(rules)
