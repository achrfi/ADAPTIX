"""Deterministic observation processing: no LLM used for parsing or filtering."""
import json
from src.adaptix.workflow.events import log


def observation_processing(state):
    clean = {'hosts': state.get('hosts', []), 'services': state.get('services', []),
             'http_services': state.get('http_services', []),
             'candidates': state.get('candidates', []),
             'browser_evidence': state.get('browser_evidence', [])}
    encoded = json.dumps(clean, ensure_ascii=False, separators=(',', ':')).encode()
    raw = int(state.get('raw_bytes', 0))
    reduction = round(100 * (1 - len(encoded) / raw), 2) if raw else 0
    planner = state.get('planner_metrics', {})
    execution = state.get('execution_metrics', {})
    return {'structured_observations': clean,
            'metrics': {'raw_bytes': raw, 'structured_bytes': len(encoded),
                        'reduction_percent': reduction,
                        'llm_calls': planner.get('llm_calls', 0),
                        'llm_tokens_used': planner.get('tokens_used', 0),
                        'planner_mode': planner.get('mode', 'rules'),
                        'tool_calls_used': execution.get('tool_calls_used', 0),
                        'tool_calls_by_tool': execution.get('by_tool', {}),
                        'hosts_scanned': len(state.get('hosts', []))},
            'events': log(state, f'Observation Processing: {raw} -> {len(encoded)} bytes')}
