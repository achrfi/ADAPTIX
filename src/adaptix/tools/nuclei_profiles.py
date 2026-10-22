"""Select trusted Nuclei tags from evidence for one HTTP origin."""
import re
from src.adaptix.config import config
from src.adaptix.security.scope import endpoint_key


def _product(value):
    if not isinstance(value, str):
        return ''
    # HTTPX uses e.g. WordPress:6.4; banners use nginx/1.26 or Apache httpd 2.4.
    name = re.split(r'(?::|/)\s*v?\d|\s+v?\d', value.strip().lower(), maxsplit=1)[0]
    return ' '.join(name.split())


def adaptive_profile(state, target):
    key = endpoint_key(target)
    if key is None:
        raise ValueError('Adaptive Nuclei selection requires an HTTP(S) endpoint')
    mapping = config('nuclei.yaml')['technology_tags']
    trusted = {}
    for product, tags in mapping.items():
        if not isinstance(tags, list) or not tags or not all(isinstance(tag, str) and re.fullmatch(r'[a-z0-9][a-z0-9_-]*', tag) for tag in tags):
            raise ValueError(f'Invalid configured Nuclei tags for {product}')
        trusted[_product(product)] = tags
    evidence, selected = [], set()

    def observe(source, field, value):
        tags = trusted.get(_product(value), [])
        if tags:
            selected.update(tags)
            item = {'source': source, 'field': field, 'product': _product(value), 'tags': tags}
            if item not in evidence:
                evidence.append(item)

    for row in state.get('http_services', []):
        observed = endpoint_key(row.get('url', ''))
        if not observed or observed[:3] != key[:3]:
            continue
        tech = row.get('tech') or []
        for value in tech if isinstance(tech, list) else [tech]:
            observe('httpx', 'tech', value)
        observe('httpx', 'webserver', row.get('webserver', ''))
    # Nmap's service facts belong to an exact host/port, including a domain's pins.
    pins = set(state.get('scope_aliases', {}).get(key[1], [])) | {key[1]}
    for row in state.get('services', []):
        try:
            matching = (row.get('host') in pins and int(row.get('port', 0)) == key[2]
                        and row.get('protocol', 'tcp') == 'tcp' and row.get('status', 'open') == 'open')
        except (ValueError, TypeError):
            matching = False
        if matching:
            observe('nmap', 'product', row.get('product', ''))
            observe('nmap', 'service', row.get('service', ''))
    tags = sorted(selected)
    return {'target': target, 'mode': 'adaptive', 'strategy': 'observed_tags' if tags else 'native_automatic',
            'tags': tags, 'evidence': evidence,
            'reason': 'Templates filtered by observed product tags' if tags else
            'No mapped product evidence: discovery seeds plus the generic observation families are selected, '
            'and native Nuclei auto-detects technology within the exact snapshot',
            'flags': ['-tags', ','.join(tags), '-pt', 'http'] if tags else ['-as', '-pt', 'http']}
