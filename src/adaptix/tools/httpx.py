"""ADAPTIX unified module. Migrated from tested running code."""
import json
from urllib.parse import urlsplit
from src.adaptix.config import config
from src.adaptix.tools.registry import tool_registry, run_tool
from src.adaptix.security.scope import allowed_url
from src.adaptix.evidence.storage import artifact_path, save_text
from src.adaptix.workflow.events import log


def httpx_probe(state):
    registry = tool_registry()
    urls = state.get('planned_urls', [])
    errors = list(state.get('errors', []))
    if not urls:
        return {'http_services': [], 'events': log(state, 'HTTPX: skipped; no HTTP endpoints')}
    if not registry['httpx']['enabled']:
        return {'http_services': [], 'events': log(state, 'HTTPX: disabled in config')}
    if not registry['httpx']['path']:
        errors.append('ProjectDiscovery HTTPX unavailable: ' + registry['httpx']['detail'])
        return {'http_services': [], 'errors': errors, 'events': log(state, 'HTTPX: missing')}
    cfg = config('scope.yaml')['limits']
    # Explicit on-disk input and stdin disabled: do not depend on CLI pipe/TTY behavior.
    # Only planned, scope-checked URLs are allowed into this file.
    targets_path = artifact_path(state, 'httpx-targets', 'combined', 'txt')
    save_text(targets_path, '\n'.join(urls) + '\n')
    argv = [registry['httpx']['path'], '-l', str(targets_path), '-no-stdin',
            '-j', '-silent', '-nc', '-nfs', '-duc',
            '-t', str(cfg['concurrent_requests']), '-rl', str(cfg['rate_per_second']),
            '-timeout', '5', '-retries', '0']
    result = run_tool(argv, timeout=max(int(cfg['timeout_seconds']), 60), stdin='')
    errors_new = errors
    if result['returncode'] != 0:
        errors_new.append('HTTPX: ' + result['stderr'][:200])
    raw = result['stdout']
    save_text(artifact_path(state, 'httpx', 'combined', 'jsonl'), raw)
    allowed_ports = {urlsplit(x).port or (443 if x.startswith('https:') else 80) for x in urls}
    def key(url):
        parsed = urlsplit(url)
        return (parsed.scheme, parsed.hostname, parsed.port or (443 if parsed.scheme == 'https' else 80))
    approved = {key(url) for url in urls}
    found = []
    for line in raw.splitlines():
        try:
            row = json.loads(line)
            url = row.get('url', '')
            if allowed_url(url, state['hosts'], allowed_ports) and key(url) in approved:
                found.append({'url': url, 'status_code': row.get('status_code'), 'title': row.get('title', ''),
                              'tech': row.get('tech', []), 'webserver': row.get('webserver', '')})
        except (json.JSONDecodeError, TypeError):
            continue
    return {'http_services': found, 'raw_bytes': state.get('raw_bytes', 0) + len(raw.encode()),
            'errors': errors_new, 'events': log(state, f'HTTPX: {len(found)} live HTTP endpoints')}
