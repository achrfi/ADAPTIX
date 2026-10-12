"""ADAPTIX unified module. Migrated from tested running code."""
import json
from urllib.parse import urlsplit
from src.adaptix.config import config, ROOT
from src.adaptix.tools.registry import tool_registry, run_tool
from src.adaptix.evidence.storage import artifact_path, save_text
from src.adaptix.workflow.events import log


def nuclei_check(state):
    registry = tool_registry()
    endpoints = [x['url'] for x in state.get('http_services', [])]
    errors = list(state.get('errors', []))
    if not endpoints:
        return {'candidates': [], 'events': log(state, 'Nuclei: skipped; no live endpoints')}
    if not registry['nuclei']['enabled']:
        return {'candidates': [], 'events': log(state, 'Nuclei: disabled in config')}
    if not registry['nuclei']['path']:
        errors.append('Nuclei unavailable: ' + registry['nuclei']['detail'])
        return {'candidates': [], 'errors': errors, 'events': log(state, 'Nuclei: missing')}
    cfg = config('scope.yaml')['limits']
    template = str(ROOT / 'templates/http-response.yaml')
    argv = [registry['nuclei']['path'], '-t', template, '-j', '-silent', '-duc',
            '-c', str(cfg['concurrent_requests']), '-rl', str(cfg['rate_per_second']), '-timeout', '5', '-dr', '-or', '-ot']
    result = run_tool(argv, timeout=max(int(cfg['timeout_seconds']), 60), stdin='\n'.join(endpoints) + '\n')
    raw = result['stdout']
    save_text(artifact_path(state, 'nuclei', 'combined', 'jsonl'), raw)
    if result['returncode'] != 0:
        errors.append('Nuclei: ' + result['stderr'][:200])
    candidates = []
    for line in raw.splitlines():
        try:
            row = json.loads(line)
            url = row.get('matched-at') or row.get('host', '')
            origin = urlsplit(url)
            normalized = f'{origin.scheme}://{origin.netloc}'
            if normalized not in endpoints:
                continue
            candidates.append({'template_id': row.get('template-id', ''),
                               'url': url, 'severity': row.get('info', {}).get('severity', 'info'),
                               'status': 'candidate_unverified'})
        except (json.JSONDecodeError, TypeError, ValueError):
            continue
    return {'candidates': candidates, 'raw_bytes': state.get('raw_bytes', 0) + len(raw.encode()),
            'errors': errors, 'events': log(state, f'Nuclei: {len(candidates)} informational candidates')}
