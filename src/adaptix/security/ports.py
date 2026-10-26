"""Validated TCP port selections shared by scope and scanner adapters."""
import re
from functools import lru_cache

MAX_PORT_SELECTION = 32


def _spec(value):
    if isinstance(value, range):
        raise ValueError('Port ranges are disabled; name individual web ports')
    if isinstance(value, (list, tuple, set)):
        if len(value) > MAX_PORT_SELECTION:
            raise ValueError(f'At most {MAX_PORT_SELECTION} explicit ports are permitted')
        value = ','.join(str(item) for item in value)
    if isinstance(value, bool) or value is None:
        raise ValueError('Port selection must name individual ports separated by commas')
    return str(value).strip().lower()


@lru_cache(maxsize=64)
def _parsed(spec):
    """Cached parse: the same selection is re-resolved for every single URL check."""
    tokens = spec.split(',')
    if len(tokens) > MAX_PORT_SELECTION:
        raise ValueError(f'At most {MAX_PORT_SELECTION} explicit ports are permitted')
    ports = set()
    for token in tokens:
        match = re.fullmatch(r'\d+', token.strip())
        if not match:
            raise ValueError(f'Invalid port selection: {token!r}')
        number = int(match[0])
        if not 1 <= number <= 65535:
            raise ValueError('Port number outside the valid TCP interval')
        ports.add(number)
    return tuple(sorted(ports))


def parse_ports(value):
    return list(_parsed(_spec(value)))


def format_ports(value):
    """Display the explicit allowlist without introducing scan ranges."""
    return ','.join(str(port) for port in parse_ports(value))


def configured_ports(limits):
    """Only the current HTTP policy can grant ports; ignore retired Nmap settings."""
    ports = set(parse_ports(limits.get('allowed_ports', '80,443')))
    if limits.get('web_ports'):
        ports.update(parse_ports(limits['web_ports']))
    return parse_ports(sorted(ports))


def ports_for_state(state, limits):
    if state.get('scope_ports'):
        return parse_ports(state['scope_ports'])
    return configured_ports(limits)
