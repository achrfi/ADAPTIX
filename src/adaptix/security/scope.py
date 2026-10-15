"""ADAPTIX unified module. Migrated from tested running code."""
import ipaddress
import socket
import re
from urllib.parse import urlsplit, urlunsplit
from src.adaptix.security.ports import parse_ports


def _safe_ip(value):
    ip = ipaddress.ip_address(value)
    if ip.is_unspecified or ip.is_multicast or ip.is_link_local or getattr(ip, 'ipv4_mapped', None):
        raise ValueError(f'IP khusus tidak dapat dipindai: {ip}')
    return ip

def _parse_target(value):
    """Allow IP, domain, CIDR, and plain scheme URLs; ignore URL path."""
    value = value.strip()
    if not value or any(ch.isspace() for ch in value):
        raise ValueError('Target kosong atau berisi whitespace')
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass
    if '://' in value or value.startswith('//'):
        parsed = urlsplit(value if '://' in value else 'http:' + value)
        if parsed.scheme not in ('http', 'https') or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError(f'URL target tidak valid: {value}')
        return canonical_host(parsed.hostname)
    if '/' in value:
        return value
    # domain:port and [IPv6]:port allowed, but port scan remains centrally configured
    parsed = urlsplit('//' + value)
    if not parsed.hostname or parsed.username or parsed.password or parsed.path:
        raise ValueError(f'Target tidak valid: {value}')
    if parsed.port is not None and not 1 <= parsed.port <= 65535:
        raise ValueError('Port target di luar batas')
    return canonical_host(parsed.hostname)

def normalize_requests(requested):
    """Normalize request identifiers for equality checks on signed grants."""
    if isinstance(requested, str):
        requested = [x.strip() for x in requested.replace(';', ',').split(',') if x.strip()]
    if not isinstance(requested, list) or not requested:
        raise ValueError('Setidaknya satu target diperlukan')
    return list(dict.fromkeys(_parse_target(str(v)) for v in requested))

def resolve_scope(requested, settings, require_allowlist=False):
    """Compact authoritative scope. CIDRs are never enumerated during authorization."""
    raw_requested = [v.strip() for v in requested.replace(';', ',').split(',') if v.strip()] if isinstance(requested, str) else list(requested)
    requested = normalize_requests(requested)
    allowed_nets = [ipaddress.ip_network(n, strict=False) for n in settings.get('allowed_cidrs', [])]
    allowed_names = {canonical_host(n) for n in settings.get('allowed_domains', [])}
    blocked = [ipaddress.ip_network(n, strict=False) for n in settings.get('blocked_cidrs', [])]
    hosts, aliases, networks, units = [], {}, [], []
    def check_ip(value):
        ip = _safe_ip(value)
        if any(ip.version == net.version and ip in net for net in blocked):
            raise ValueError(f'IP dalam jaringan yang diblokir kebijakan: {ip}')
        return str(ip)
    for target in requested:
        if '/' in target:
            net = ipaddress.ip_network(target, strict=False)
            if any(net.version == bad.version and net.overlaps(bad) for bad in blocked):
                raise ValueError('CIDR intersects blocked addresses')
            # These special classes remain policy exclusions independent of scope size.
            if net.network_address.is_multicast or net.network_address.is_link_local or net.network_address.is_unspecified:
                raise ValueError('CIDR contains special IP addresses')
            if require_allowlist and not any(net.version == n.version and net.subnet_of(n) for n in allowed_nets):
                raise ValueError(f'CIDR di luar allowlist: {net}')
            networks.append(net)
            continue
        try:
            ipaddress.ip_address(target)
        except ValueError:
            if require_allowlist and target not in allowed_names:
                raise ValueError(f'Domain di luar allowlist: {target}')
            try:
                resolved = sorted({check_ip(row[4][0]) for row in socket.getaddrinfo(target, None, type=socket.SOCK_STREAM)})
            except socket.gaierror as exc:
                raise ValueError(f'Gagal DNS untuk {target}') from exc
            if not resolved:
                raise ValueError('Domain has no resolved addresses')
            aliases[target] = resolved
            hosts.extend(resolved)
            units.append(target)
        else:
            ip = check_ip(target)
            if require_allowlist and not any(ipaddress.ip_address(ip).version == n.version and ipaddress.ip_address(ip) in n for n in allowed_nets):
                raise ValueError(f'IP di luar allowlist: {ip}')
            hosts.append(ip)
            units.append(ip)
    collapsed = []
    for version in (4, 6):
        collapsed.extend(ipaddress.collapse_addresses(n for n in networks if n.version == version))
    selected_units = []
    for raw in raw_requested:
        value = str(raw).strip()
        if '://' in value or value.startswith('//'):
            selected_units.append(canonical_url(value if '://' in value else 'http:' + value))
        else:
            value = _parse_target(value)
            if '/' not in value:
                selected_units.append(value)
    units = [u for u in dict.fromkeys(selected_units) if '://' in u or u in aliases or not any(ipaddress.ip_address(u).version == n.version and ipaddress.ip_address(u) in n for n in collapsed)]
    return {'targets': requested, 'hosts': list(dict.fromkeys(hosts)), 'aliases': aliases,
            'networks': [str(n) for n in collapsed], 'units': units,
            'total_units': len(units) + sum(network_host_count(n) for n in collapsed)}


def network_host_count(network):
    net = ipaddress.ip_network(network) if isinstance(network, str) else network
    excluded = 2 if net.version == 4 and net.prefixlen < 31 else 1 if net.version == 6 and net.prefixlen < 127 else 0
    return net.num_addresses - excluded


def iter_scope_units(manifest):
    yield from manifest['units']
    for value in manifest['networks']:
        for ip in ipaddress.ip_network(value).hosts():
            yield str(ip)


def scope_contains_ip(value, manifest):
    try:
        ip = _safe_ip(value)
        return str(ip) in manifest['hosts'] or any(ip.version == n.version and ip in n for n in map(ipaddress.ip_network, manifest.get('networks', [])))
    except ValueError:
        return False


def scope_is_loopback(manifest):
    return (all(ipaddress.ip_address(ip).is_loopback for ip in manifest['hosts'])
            and all(n.subnet_of(ipaddress.ip_network('127.0.0.0/8' if n.version == 4 else '::1/128')) for n in map(ipaddress.ip_network, manifest['networks'])))


def scope_window(manifest, handled, count):
    """A window limits model context, not authorization or overall scope."""
    result = []
    handled = set(handled)
    for unit in iter_scope_units(manifest):
        if unit not in handled:
            result.append(unit)
            if len(result) >= count:
                break
    return result


def expand_targets(requested, settings, require_allowlist=True):
    """Legacy materializing helper. Production uses resolve_scope and scope_window."""
    manifest = resolve_scope(requested, settings, require_allowlist)
    result = list(manifest['hosts'])
    result.extend(str(ip) for n in manifest['networks'] for ip in ipaddress.ip_network(n).hosts())
    return list(dict.fromkeys(result))


def allowed_url(url, hosts, ports, aliases=None, networks=None):
    try:
        parsed = urlsplit(url)
        if parsed.scheme not in ('http', 'https') or not parsed.hostname:
            return False
        if parsed.username or parsed.password:
            return False
        host = canonical_host(parsed.hostname)
        in_network = scope_contains_ip(host, {'hosts': [], 'networks': networks or []})
        if host not in set(hosts) and not in_network:
            pins = (aliases or {}).get(host, [])
            if not pins or not set(pins).issubset(set(hosts)):
                return False
        return (parsed.port or (443 if parsed.scheme == 'https' else 80)) in ports
    except (ValueError, TypeError):
        return False


def endpoint_key(url):
    """Normalize only harmless URL variations; preserve path and query identity."""
    try:
        parsed = urlsplit(url)
        if parsed.scheme not in ('http', 'https') or not parsed.hostname or parsed.username or parsed.password:
            return None
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        path = parsed.path.rstrip('/') or '/'
        hostname = parsed.hostname.lower().rstrip('.')
        return (parsed.scheme, hostname, port, path, parsed.query)
    except (TypeError, ValueError):
        return None


def canonical_host(host):
    host = host.rstrip('.').lower()
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        host = host.encode('idna').decode('ascii')
        if len(host) > 253 or not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label) for label in host.split('.')):
            raise ValueError('Invalid DNS hostname')
        return host


def domain_aliases(requested, hosts, policy):
    aliases = resolve_scope(requested, policy)['aliases']
    if not all(set(pins).issubset(set(hosts)) for pins in aliases.values()):
        raise ValueError('DNS changed while pinning scope')
    return aliases


def scope_ports(requested, policy):
    ports = set(parse_ports(policy['limits']['nmap_ports']))
    ports.update((80, 443))
    values = [requested] if isinstance(requested, str) else requested
    for value in values:
        value = str(value)
        if '://' in value or value.startswith('//'):
            parsed = urlsplit(value if '://' in value else 'http:' + value)
            if parsed.port is not None:
                if not 1 <= parsed.port <= 65535:
                    raise ValueError('Invalid target port')
                ports.add(parsed.port)
    return sorted(ports)


def is_scope_unit(value, manifest):
    if value in manifest['units']:
        return True
    try:
        ip = ipaddress.ip_address(value)
        for n in map(ipaddress.ip_network, manifest['networks']):
            if ip.version != n.version or ip not in n:
                continue
            if n.version == 4 and n.prefixlen < 31 and ip in (n.network_address, n.broadcast_address):
                continue
            if n.version == 6 and n.prefixlen < 127 and ip == n.network_address:
                continue
            return True
    except ValueError:
        pass
    return False


def unit_host(unit):
    return canonical_host(urlsplit(unit).hostname) if '://' in unit else unit


def canonical_url(value):
    parsed = urlsplit(value)
    host = canonical_host(parsed.hostname)
    address = '[' + host + ']' if ':' in host else host
    port = parsed.port
    if port is not None and not 1 <= port <= 65535:
        raise ValueError('Invalid target port')
    if port and port != (443 if parsed.scheme == 'https' else 80):
        address += ':' + str(port)
    return urlunsplit((parsed.scheme.lower(), address, parsed.path.rstrip('/') or '/', parsed.query, ''))


def action_scope_units(action, state, manifest):
    if action['tool'] == 'nmap':
        host, url = action['target'], None
    elif action['tool'] == 'scenario':
        match = next((s for s in state.get('scenario_candidates', []) if s.get('name') == action['target']), {})
        url = match.get('url')
        host = urlsplit(url).hostname if url else None
    elif action['tool'] == 'idor':
        match = next((s for s in state.get('idor_scenarios', []) if s.get('name') == action['target']), {})
        url = match.get('base_url', '').rstrip('/') + match.get('path_template', '').format(object_id=match.get('object_id', ''))
        host = urlsplit(url).hostname
    else:
        url = action['target']
        host = urlsplit(url).hostname
    if host:
        host = canonical_host(host)
    candidates = [host] if host else []
    if url:
        key = endpoint_key(canonical_url(url))
        candidates.extend(u for u in manifest['units'] if '://' in u and endpoint_key(u) == key)
    candidates.extend(name for name, pins in manifest.get('aliases', {}).items() if host in pins)
    return list(dict.fromkeys(u for u in candidates if is_scope_unit(u, manifest)))
