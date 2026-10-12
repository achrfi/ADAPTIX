"""ADAPTIX unified module. Migrated from tested running code."""
import json
from src.adaptix.workflow.events import log


def observation_processing(state):
    """Only small structured observations go into the future model context."""
    clean = {'hosts': state.get('hosts', []), 'services': state.get('services', []),
             'http_services': state.get('http_services', []),
             'candidates': state.get('candidates', []),
             'browser_evidence': state.get('browser_evidence', [])}
    encoded = json.dumps(clean, ensure_ascii=False, separators=(',', ':')).encode()
    raw = int(state.get('raw_bytes', 0))
    reduction = round(100 * (1 - len(encoded) / raw), 2) if raw else 0
    planner_metrics = state.get('planner_metrics', {})
    return {'structured_observations': clean,
            'metrics': {'raw_bytes': raw, 'structured_bytes': len(encoded),
                        'reduction_percent': reduction,
                        'llm_calls': planner_metrics.get('tool_calls_used', 0),
                        'llm_tokens_used': planner_metrics.get('tokens_used', 0),
                        'planner_mode': planner_metrics.get('mode', 'rules'),
                        'hosts_scanned': len(state.get('hosts', []))},
            'events': log(state, f'Observation Processing: {raw} -> {len(encoded)} bytes')}
