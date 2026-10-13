"""ADAPTIX unified module. Migrated from tested running code."""
import ipaddress
import socket
from urllib.parse import urlsplit


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
    if '://' in value or value.startswith('//'):
        parsed = urlsplit(value if '://' in value else 'http:' + value)
        if parsed.scheme not in ('http', 'https') or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError(f'URL target tidak valid: {value}')
        return parsed.hostname.rstrip('.').lower()
    if '/' in value:
        return value
    # domain:port and [IPv6]:port allowed, but port scan remains centrally configured
    parsed = urlsplit('//' + value)
    if not parsed.hostname or parsed.username or parsed.password or parsed.path:
        raise ValueError(f'Target tidak valid: {value}')
    if parsed.port is not None and not 1 <= parsed.port <= 65535:
        raise ValueError('Port target di luar batas')
    return parsed.hostname.rstrip('.').lower()

def normalize_requests(requested):
    """Normalize request identifiers for equality checks on signed grants."""
    if isinstance(requested, str):
        requested = [x.strip() for x in requested.replace(';', ',').split(',') if x.strip()]
    if not isinstance(requested, list) or not requested:
        raise ValueError('Setidaknya satu target diperlukan')
    if len(requested) > 128:
        raise ValueError('Terlalu banyak entri target')
    return list(dict.fromkeys(_parse_target(str(v)) for v in requested))

def expand_targets(requested, settings, require_allowlist=True):
    """Bound and validate targets, optionally using signed grant instead of static allowlist.

    For domain inputs, return resolved IPs (DNS pinning); scanner never re-resolves.
    """
    requested = normalize_requests(requested)
    limits = settings['limits']
    max_hosts = int(limits['max_hosts'])
    approved_nets = [ipaddress.ip_network(n, strict=False) for n in settings.get('allowed_cidrs', [])]
    approved_names = set(str(n).strip('.').lower() for n in settings.get('allowed_domains', []))
    blocked_nets = [ipaddress.ip_network(n, strict=False) for n in settings.get('blocked_cidrs', [])]
    def check_address(value):
        ip = _safe_ip(value)
        if any(ip in net for net in blocked_nets):
            raise ValueError(f'IP dalam jaringan yang diblokir kebijakan: {ip}')
        return ip
    expanded = []
    for host in requested:
        if '/' in host:
            try:
                net = ipaddress.ip_network(host, strict=False)
            except ValueError as exc:
                raise ValueError(f'CIDR tidak valid: {host}') from exc
            if require_allowlist and not any(net.subnet_of(allowed) for allowed in approved_nets):
                raise ValueError(f'CIDR di luar allowlist: {net}')
            if net.num_addresses > max_hosts + 2:
                raise ValueError(f'CIDR terlalu besar; max_hosts={max_hosts}')
            hosts = list(net.hosts())
            if not hosts and net.num_addresses == 1:
                hosts = [net.network_address]
            expanded.extend(str(check_address(ip)) for ip in hosts)
        else:
            try:
                ip = check_address(host)
            except ValueError as exc:
                # Invalid IP-like host strings must not be mistaken for domains
                if all(c in '0123456789.:' for c in host):
                    raise ValueError(f'IP tidak valid: {host}') from exc
                if require_allowlist and host not in approved_names:
                    raise ValueError(f'Domain di luar allowlist: {host}')
                try:
                    addr = {row[4][0] for row in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)}
                except socket.gaierror as dns_exc:
                    raise ValueError(f'Gagal DNS untuk {host}: {dns_exc}') from dns_exc
                if not addr:
                    raise ValueError(f'Tidak ada DNS A/AAAA: {host}')
                expanded.extend(str(check_address(ip_string)) for ip_string in sorted(addr))
            else:
                if require_allowlist and not any(ip in network for network in approved_nets):
                    raise ValueError(f'IP di luar allowlist: {ip}')
                expanded.append(str(ip))
        if len(set(expanded)) > max_hosts:
            raise ValueError(f'Melebihi limit host: {max_hosts}')
    return list(dict.fromkeys(expanded))

def allowed_url(url, hosts, ports):
    try:
        parsed = urlsplit(url)
        if parsed.scheme not in ('http', 'https') or not parsed.hostname:
            return False
        if parsed.username or parsed.password:
            return False
        if parsed.hostname.rstrip('.').lower() not in set(hosts):
            return False
        return (parsed.port or (443 if parsed.scheme == 'https' else 80)) in ports
    except ValueError:
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
