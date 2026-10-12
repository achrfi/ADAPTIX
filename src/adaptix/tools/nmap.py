"""ADAPTIX unified module. Migrated from tested running code."""
import xml.etree.ElementTree as ET
from src.adaptix.config import config
from src.adaptix.tools.registry import tool_registry, run_tool
from src.adaptix.evidence.storage import artifact_path, save_text
from src.adaptix.workflow.events import log


def reconnaissance(state):
    cfg = config('scope.yaml')['limits']
    registry = tool_registry()
    errors = list(state.get('errors', []))
    services = []
    raw_bytes = int(state.get('raw_bytes', 0))
    if not registry['nmap']['enabled']:
        return {'services': [], 'events': log(state, 'Reconnaissance: Nmap disabled in config')}
    if not registry['nmap']['path']:
        errors.append('Nmap unavailable: ' + registry['nmap']['detail'])
        return {'services': services, 'errors': errors, 'events': log(state, 'Reconnaissance: Nmap missing')}
    for host in state['hosts']:
        argv = [registry['nmap']['path'], '-Pn', '-sT', '-sV', '--version-light', '-n',
                '-p', str(cfg['nmap_ports']), '-oX', '-', host]
        if ':' in host:
            argv.insert(1, '-6')
        result = run_tool(argv, timeout=int(cfg['timeout_seconds']))
        raw_bytes += len(result['stdout'].encode())
        if result['stdout']:
            save_text(artifact_path(state, 'nmap', host, 'xml'), result['stdout'])
        if result['returncode'] != 0:
            errors.append(f'Nmap {host}: {result["stderr"][:180]}')
            continue
        try:
            root = ET.fromstring(result['stdout'])
            for p in root.findall('.//port'):
                if p.find('state') is None or p.find('state').get('state') != 'open':
                    continue
                info = p.find('service')
                services.append({'host': host, 'port': int(p.get('portid')), 'protocol': p.get('protocol'),
                                 'service': info.get('name', '') if info is not None else '',
                                 'product': info.get('product', '') if info is not None else '',
                                 'version': info.get('version', '') if info is not None else '',
                                 'tunnel': info.get('tunnel', '') if info is not None else ''})
        except ET.ParseError as exc:
            errors.append(f'Nmap XML invalid ({host}): {exc}')
    return {'services': services, 'raw_bytes': raw_bytes, 'errors': errors,
            'events': log(state, f'Reconnaissance: {len(services)} open services')}
