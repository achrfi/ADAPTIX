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


def adaptive_profile(state, target, mode='adaptive'):
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
    # Route-surface evidence: a discovered route's own shape is proof that a
    # functional class of endpoint exists. These generic tags (api/graphql/swagger/
    # jwt) are matched structurally from path segments, never from a product name
    # or a hardcoded application path, and each selected tag keeps the routes that
    # justified it so the choice is auditable.
    surface = _surface_tags(state, key)
    for tag, routes in surface.items():
        selected.add(tag)
        evidence.append({'source': 'web_routes', 'field': 'endpoint_surface', 'product': tag,
                         'tags': [tag], 'routes': sorted(routes)[:5]})
    tags = sorted(selected)
    # In assessment mode the manifest keeps full vulnerability-family coverage and
    # evidence only re-ranks which rows survive the cap: passing `-tags` there
    # would make the engine silently drop the manifest's non-matching templates
    # (and can abort the scan entirely), so declared coverage would lie. Tag
    # filtering therefore applies only to adaptive mode, whose selection filter is
    # tag-based to begin with; assessment relies on the manifest's explicit -t set.
    # Include vulnerability detection tags when present in observed evidence.
    vuln_tags = selected.intersection(VULN_TEMPLATE_TAGS) if selected else set()
    all_tags = sorted(selected | vuln_tags)
    restrict = bool(all_tags) and mode == 'adaptive'
    return {'target': target, 'mode': mode, 'strategy': 'observed_tags' if all_tags else 'native_automatic',
            'tags': all_tags, 'evidence': evidence,
            'reason': ('Templates filtered by observed product and vulnerability tags' if restrict else
                       'Observed evidence re-ranks template selection; full family coverage retained'
                       if all_tags else
                       'No mapped product evidence: discovery seeds plus the generic observation families are '
                       'selected, and native Nuclei auto-detects technology within the exact snapshot'),
            'flags': ['-tags', ','.join(all_tags), '-pt', 'http'] if restrict else
                     (['-pt', 'http'] if all_tags else ['-as', '-pt', 'http'])}


# Structural path-segment tokens that prove a functional endpoint class exists.
# These are generic API-surface names, not application-specific routes, so the
# same rule fires on any target that exposes the surface.
_SURFACE_TOKENS = {
    'graphql': ('graphql', 'gql'),
    'swagger': ('swagger', 'openapi'),
    'api': ('api', 'rest', 'v1', 'v2', 'v3'),
}

# Vulnerability template categories that can detect real vulnerabilities.
# These tags map to vulnerability detection capabilities in Nuclei templates.
VULN_TEMPLATE_TAGS = {
    'sqli', 'xss', 'lfi', 'rce', 'ssrf', 'traversal',
    'vuln', 'cve', 'injection', 'redirect', 'auth',
    'dos', 'csrf', 'xxe', 'ssti'
}


def _surface_tags(state, key):
    """Map discovered route shapes to generic API-surface tags.

    Evidence is the set of in-scope routes on the same origin whose path segments
    contain a surface token. Nothing is inferred from a product name or a known
    application path, and a route only contributes its own URL as justification.
    """
    surface = {}
    for row in state.get('web_routes', []):
        url = row.get('url', '')
        observed = endpoint_key(url)
        if not observed or observed[:3] != key[:3]:
            continue
        segments = {segment.lower() for segment in (observed[3] or '').split('/') if segment}
        for tag, tokens in _SURFACE_TOKENS.items():
            if segments.intersection(tokens):
                surface.setdefault(tag, set()).add(url)
    return surface
