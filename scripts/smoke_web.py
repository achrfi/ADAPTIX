"""Bounded, non-destructive smoke test for the generic web adapters.

Drives scope validation, web discovery, a control request and one benign probe
request against a live target, then prints the deterministic findings. It never
uses the planner/LLM and never issues state-changing methods or reads lab
solutions.

Usage: .venv/bin/python scripts/smoke_web.py http://127.0.0.1:3000/
"""
import json
import sys
import time
import uuid

from src.adaptix.evidence.web_signatures import build_findings
from src.adaptix.tools import web
from src.adaptix.workflow.nodes import scope_guard

CANARY = "'\"<>"


def main():
    seed = sys.argv[1] if len(sys.argv) > 1 else 'http://127.0.0.1:3000/'
    state = {'target': [seed], 'run_id': 'smoke-' + uuid.uuid4().hex[:8], 'events': [], 'errors': [],
             'tool_call_budget': 12, 'iterations': 0, 'time_budget_seconds': 60,
             'run_started_at': time.time(), 'execution_metrics': {}, 'raw_bytes': 0}
    state.update(scope_guard(state))
    if state.get('status') != 'scope_ok':
        print('scope blocked:', state.get('errors'))
        return 1
    state['planned_actions'] = [{'tool': 'web_discover', 'target': seed}]
    state.update(web.web_discover(state))
    print(f"discovered {len(state.get('web_routes', []))} in-scope routes")
    for row in state.get('web_routes', [])[:8]:
        print('  route', row['method'], row['url'])

    get_routes = [row['url'] for row in state.get('web_routes', [])
                  if row['method'] == 'GET' and row['kind'] in ('link', 'document')][:2]
    for url in get_routes:
        state['planned_actions'] = [{'tool': 'http_request', 'target': url, 'method': 'GET'}]
        state.update(web.http_request(state))
    probe = get_routes[0] if get_routes else seed
    joiner = '&' if '?' in probe else '?'
    probe = f'{probe}{joiner}adaptix_probe={CANARY}'
    state['planned_actions'] = [{'tool': 'http_request', 'target': probe, 'method': 'GET'}]
    state.update(web.http_request(state))

    print(f"recorded {len(state.get('probe_traces', []))} response traces")
    findings = build_findings(state)
    print(json.dumps(findings, indent=2, ensure_ascii=False))
    print('errors:', state.get('errors', []))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
