"""Deterministic observation processing: no LLM used for parsing or filtering."""
import json
import time
from src.adaptix.processing.normalize import deduplicate
from src.adaptix.workflow.events import log


def observation_processing(state):
    kinds = ('services', 'recon_inventory', 'http_services', 'candidates', 'browser_evidence', 'idor_findings',
             'web_routes', 'probe_traces', 'request_audit')
    if 'ffuf_observations' in state:
        kinds += ('ffuf_observations',)
    clean = {kind: deduplicate(kind, state.get(kind, [])) for kind in kinds}
    clean['hosts'] = list(dict.fromkeys(state.get('hosts', [])))
    encoded = json.dumps(clean, ensure_ascii=False, separators=(',', ':')).encode()
    raw = int(state.get('raw_bytes', 0))
    reduction = round(100 * max(0, raw - len(encoded)) / raw, 2) if raw else 0
    expansion = round(100 * max(0, len(encoded) - raw) / raw, 2) if raw else 0
    planner = state.get('planner_metrics', {})
    execution = state.get('execution_metrics', {})
    outcomes = state.get('action_outcomes', [])
    failures = sum(bool(o.get('failed')) for o in outcomes)
    return {**{k: clean[k] for k in kinds if k in state}, 'structured_observations': clean,
            'metrics': {'raw_bytes': raw, 'structured_bytes': len(encoded),
                        'reduction_percent': reduction,
                        'expansion_percent': expansion,
                        'evidence_overhead_bytes': max(0, len(encoded) - raw),
                        'size_comparison': 'no_raw_output' if not raw else 'expanded' if len(encoded) > raw else 'reduced' if len(encoded) < raw else 'unchanged',
                        'deduplicated_records': sum(len(state.get(k, [])) - len(clean[k]) for k in kinds),
                        'candidate_count': len(clean['candidates']), 'tool_failures': failures,
                        'probe_evidence_rows': len(clean.get('probe_traces', [])),
                        'request_attempts': len(clean.get('request_audit', [])),
                        'tool_error_rate': failures / len(outcomes) if outcomes else 0,
                        'tool_seconds': sum(o.get('seconds', 0) for o in outcomes),
                        'execution_seconds': max(0, time.time() - state.get('run_started_at', time.time())),
                        'planner_seconds': planner.get('seconds', 0),
                        'llm_calls': planner.get('llm_calls', 0),
                        'llm_tokens_used': planner.get('tokens_used', 0),
                        'llm_tokens_provider_reported': sum(e.get('tokens_charged', 0) for e in state.get('token_ledger', []) if e.get('source') == 'provider'),
                        'llm_tokens_reserved': sum(e.get('tokens_charged', 0) for e in state.get('token_ledger', []) if e.get('source') == 'reservation'),
                        'planner_mode': planner.get('mode', 'rules'),
                        'tool_calls_used': execution.get('tool_calls_used', 0),
                        'tool_calls_by_tool': execution.get('by_tool', {}),
                        'hosts_scanned': len(clean['recon_inventory'])},
            'events': log(state, f'Observation Processing: {raw} -> {len(encoded)} bytes')}
