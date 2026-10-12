"""ADAPTIX unified module. Migrated from tested running code."""
from src.adaptix.workflow.events import log


def final_report(state):
    report = {'status': 'completed_with_errors' if state.get('errors') else 'scan_completed',
              'mode': 'deterministic_baseline', 'target': state.get('target'),
              'authorization': state.get('authorization', {}),
              'hosts': state.get('hosts', []), 'iterations': state.get('iterations', 0),
              'services': state.get('services', []), 'http_services': state.get('http_services', []),
              'candidates': state.get('candidates', []), 'verified_findings': state.get('verified_findings', []),
              'rejected_findings': state.get('rejected_findings', []),
              'inconclusive_findings': state.get('inconclusive_findings', []),
              'stop_reason': state.get('stop_reason'),
              'browser_evidence': state.get('browser_evidence', []), 'metrics': state.get('metrics', {}),
              'errors': state.get('errors', [])}
    return {'status': report['status'], 'report': report,
            'events': log(state, f'Final Report: {report["status"]}')}

def blocked_report(state):
    report = {'status': 'scope_blocked', 'target': state.get('target'), 'hosts': [],
              'verified_findings': [], 'errors': state.get('errors', []), 'metrics': {'llm_calls': 0}}
    return {'report': report, 'events': log(state, 'Final Report: scope_blocked')}
