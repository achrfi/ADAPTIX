"""Validated TCP port selections shared by scope and scanner adapters."""
import re


def parse_ports(value):
    """Accept 'all', Nmap-style comma/range notation, or a list of ports."""
    if isinstance(value, (list, tuple, set, range)):
        value = ','.join(str(item) for item in value)
    if isinstance(value, bool) or value is None:
        raise ValueError('Port selection must be all, a port, or comma-separated ranges')
    spec = str(value).strip().lower()
    if spec in ('all', '-'):
        return list(range(1, 65536))
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
    return sorted(ports)


def format_ports(value):
    """Collapse consecutive ports without changing selection or model context size."""
    ports = parse_ports(value)
    ranges = []
    start = end = ports[0]
    for port in ports[1:]:
        if port == end + 1:
            end = port
        else:
            ranges.append(str(start) if start == end else f'{start}-{end}')
            start = end = port
    ranges.append(str(start) if start == end else f'{start}-{end}')
    return ','.join(ranges)


def ports_for_state(state, limits):
    return parse_ports(state.get('scope_ports') or limits['nmap_ports'])
