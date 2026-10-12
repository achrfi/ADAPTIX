"""ADAPTIX unified module. Migrated from tested running code."""
from src.adaptix.config import config
from src.adaptix.workflow.events import log


def adaptive_planning(state):
    # Intentionally deterministic at Iteration 3; AI planning arrives with Ollama later.
    ports = {80, 443, 8080, 8443, 18080}
    selected = []
    for svc in state.get('services', []):
        name = svc['service'].lower()
        if 'http' not in name and svc['port'] not in ports:
            continue
        host = svc['host']
        if ':' in host:
            host = f'[{host}]'
        scheme = 'https' if svc['port'] in (443, 8443, 9443) or svc['tunnel'] == 'ssl' else 'http'
        selected.append(f'{scheme}://{host}:{svc["port"]}')
    selected = list(dict.fromkeys(selected))[:int(config('scope.yaml')['limits']['max_web_urls'])]
    return {'planned_urls': selected, 'events': log(state, f'Adaptive Planning (rules): {len(selected)} HTTP endpoints')}
