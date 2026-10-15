"""ADAPTIX unified module. Migrated from tested running code."""
import xml.etree.ElementTree as ET
import time
from src.adaptix.config import config
from src.adaptix.tools.registry import tool_registry, run_tool
from src.adaptix.evidence.storage import artifact_path, save_text
from src.adaptix.workflow.events import log
from src.adaptix.workflow.budget import tool_budget_available, record_tool_call, tool_timeout
from src.adaptix.security.ports import ports_for_state, format_ports


def parse_inventory(xml, requested_host, timestamp=None):
    """Parse complete host/port status; missing records stay unknown, never open."""
    root = ET.fromstring(xml)
    if root.tag != 'nmaprun':
        raise ValueError('Expected nmaprun XML root')
    timestamp = timestamp or int(time.time())
    inventory, warnings = [], []
    for node in root.findall('host'):
        status = node.find('status')
        host_status = status.get('state', 'unknown') if status is not None else 'unknown'
        ports = []
        for port in node.findall('./ports/port'):
            try:
                number = int(port.get('portid', ''))
                if not 1 <= number <= 65535:
                    raise ValueError('port outside valid range')
            except ValueError:
                warnings.append('invalid/missing port number')
                continue
            status_node, info = port.find('state'), port.find('service')
            ports.append({'port': number, 'protocol': port.get('protocol', 'unknown'),
                          'status': status_node.get('state', 'unknown') if status_node is not None else 'unknown',
                          **{k: info.get(k, '') if info is not None else ''
                             for k in ('name', 'product', 'version', 'tunnel')}})
        inventory.append({'host': requested_host, 'status': host_status,
                          'timestamp': timestamp, 'ports': ports})
    if not inventory:
        warnings.append('XML contains no host records')
        inventory = [{'host': requested_host, 'status': 'unknown', 'timestamp': timestamp, 'ports': []}]
    return inventory, warnings


def reconnaissance(state):
    cfg = config('scope.yaml')['limits']
    registry = tool_registry()
    errors = list(state.get('errors', []))
    services = []
    inventory = list(state.get('recon_inventory', []))
    raw_bytes = int(state.get('raw_bytes', 0))
    port_spec = format_ports(ports_for_state(state, cfg))
    if not registry['nmap']['enabled']:
        return {'services': [], 'events': log(state, 'Reconnaissance: Nmap disabled in config')}
    if not registry['nmap']['path']:
        errors.append('Nmap unavailable: ' + registry['nmap']['detail'])
        return {'services': services, 'errors': errors, 'events': log(state, 'Reconnaissance: Nmap missing')}
    execution_metrics = dict(state.get('execution_metrics', {}))
    for host in state['hosts']:
        if not tool_budget_available({**state, 'execution_metrics': execution_metrics}):
            errors.append('Nmap: tool-call budget exhausted before all hosts could be scanned')
            break
        argv = [registry['nmap']['path'], '-Pn', '-sT', '-sV', '--version-light', '-n',
                '-p', port_spec, '-oX', '-', host]
        if ':' in host:
            argv.insert(1, '-6')
        result = run_tool(argv, timeout=tool_timeout(state, int(cfg.get('nmap_timeout_seconds', cfg['timeout_seconds']))))
        execution_metrics = record_tool_call({**state, 'execution_metrics': execution_metrics}, 'nmap')
        raw_bytes += len(result['stdout'].encode())
        if result['stdout']:
            save_text(artifact_path(state, 'nmap', host, 'xml'), result['stdout'])
        if result['returncode'] != 0:
            errors.append(f'Nmap {host}: {result["stderr"][:180]}')
            inventory.append({'host': host, 'status': 'error', 'timestamp': int(time.time()),
                              'ports': [], 'error': result['stderr'][:180]})
            continue
        try:
            records, warnings = parse_inventory(result['stdout'], host)
            inventory.extend(records)
            errors.extend(f'Nmap {host}: {w}' for w in warnings)
            for record in records:
                for p in record['ports']:
                    if p['status'] == 'open' and record['status'] != 'down':
                        services.append({'host': host, 'port': p['port'], 'protocol': p['protocol'],
                                         'service': p['name'], 'product': p['product'], 'version': p['version'],
                                         'tunnel': p['tunnel'], 'status': 'open', 'timestamp': record['timestamp']})
        except (ET.ParseError, ValueError) as exc:
            errors.append(f'Nmap XML invalid ({host}): {exc}')
            inventory.append({'host': host, 'status': 'error', 'timestamp': int(time.time()), 'ports': [],
                              'error': 'Invalid XML'})
    return {'services': services, 'recon_inventory': inventory, 'execution_metrics': execution_metrics, 'raw_bytes': raw_bytes, 'errors': errors,
            'events': log(state, f'Reconnaissance: {len(services)} open services')}
