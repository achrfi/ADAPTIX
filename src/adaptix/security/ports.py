"""Validated TCP port selections shared by scope and scanner adapters."""
import re
from functools import lru_cache


def _spec(value):
    if isinstance(value, (list, tuple, set, range)):
        value = ','.join(str(item) for item in value)
    if isinstance(value, bool) or value is None:
        raise ValueError('Port selection must be \'all\', a port, or comma-separated ranges')
    return str(value).strip().lower()


@lru_cache(maxsize=64)
def _parsed(spec):
    """Cached parse: the same selection is re-resolved for every single URL check."""
    if spec in ('all', '-'):
        return tuple(range(1, 65536))
    ports = set()
    for token in spec.split(','):
        match = re.fullmatch(r'(\d+)(?:\s*-\s*(\d+))?', token.strip())
        if not match:
            raise ValueError(f'Invalid port selection: {token!r}')
        start = int(match[1])
        end = int(match[2] or start)
        if not 1 <= start <= end <= 65535:
            raise ValueError('Ports must be between 1 and 65535 with ascending ranges')
        ports.update(range(start, end + 1))
    return tuple(sorted(ports))


def parse_ports(value):
    return list(_parsed(_spec(value)))


def format_ports(value):
    """Collapse consecutive ports without changing selection or model context size."""
    ports = parse_ports(value)
    ranges = []
    start = end = ports[0]
    for port in ports[1:]:
        if port == end + 1:
            end = port
        else:
            ranges.append(f'{start}' if start == end else f'{start}-{end}')
            start = end = port
    ranges.append(f'{start}' if start == end else f'{start}-{end}')
    return ','.join(ranges)


def ports_for_state(state, limits):
    if state.get('scope_ports'):
        return parse_ports(state['scope_ports'])
    ports = set(parse_ports(limits['nmap_ports']))
    if limits.get('web_ports'):
        ports.update(parse_ports(limits['web_ports']))
    return sorted(ports)
