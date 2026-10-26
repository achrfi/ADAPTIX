"""Historical Nmap XML parser. Live Nmap execution has been retired."""
import xml.etree.ElementTree as ET
import time
from src.adaptix.workflow.events import log


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
    """Fail closed for old direct imports, including callers with a stale registry."""
    return {'events': log(state, 'Reconnaissance: Nmap retired; provide an explicit HTTP URL')}
