"""ADAPTIX unified module. Iterasi 5: evidence-driven verification with explicit reasons."""
import time
from src.adaptix.workflow.events import log

SEVERITY_WEIGHT = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0}
MIN_SEVERITY_FOR_VERIFICATION = 'medium'


def _build_evidence(candidate, http_match, idx):
    return {
        'evidence_id': f'EV-{idx:03d}',
        'source_tool': 'nuclei',
        'target': candidate.get('url', ''),
        'timestamp': int(time.time()),
        'observation_type': 'service',
        'template_id': candidate.get('template_id', ''),
        'severity': candidate.get('severity', 'info'),
        'expected_evidence': 'live HTTP service matching candidate URL with 2xx/3xx response',
        'actual_observation': {
            'status_code': http_match.get('status_code') if http_match else None,
            'title': http_match.get('title', '') if http_match else None,
        } if http_match else None,
        'confidence': 'low',
    }


def reflection_verification(state):
    candidates = state.get('candidates', [])
    http_by_url = {svc['url']: svc for svc in state.get('http_services', [])}

    verified, rejected, inconclusive = [], [], []
    for idx, candidate in enumerate(candidates, start=1):
        severity = candidate.get('severity', 'info')
        http_match = http_by_url.get(candidate.get('url'))
        evidence = _build_evidence(candidate, http_match, idx)

        if SEVERITY_WEIGHT.get(severity, 0) < SEVERITY_WEIGHT[MIN_SEVERITY_FOR_VERIFICATION]:
            evidence['verification_status'] = 'rejected'
            evidence['reason'] = f'severity "{severity}" below verification threshold ({MIN_SEVERITY_FOR_VERIFICATION}); informational only'
            rejected.append(evidence)
            continue

        if not http_match:
            evidence['verification_status'] = 'inconclusive'
            evidence['reason'] = 'no corresponding live HTTP observation to cross-check candidate'
            inconclusive.append(evidence)
            continue

        status_code = http_match.get('status_code')
        if status_code and 200 <= int(status_code) < 400:
            evidence['confidence'] = 'medium'
            evidence['verification_status'] = 'verified'
            evidence['reason'] = f'candidate corroborated by live HTTP response ({status_code}) at same asset'
            verified.append(evidence)
        else:
            evidence['verification_status'] = 'rejected'
            evidence['reason'] = f'HTTP cross-check returned status {status_code}; expected evidence not matched'
            rejected.append(evidence)

    total_candidates = len(candidates)
    stop_reason = None
    if total_candidates and not verified and (len(rejected) + len(inconclusive)) == total_candidates:
        stop_reason = 'all_candidates_rejected_or_inconclusive'

    return {
        'verified_findings': verified,
        'rejected_findings': rejected,
        'inconclusive_findings': inconclusive,
        'stop_reason': stop_reason,
        'events': log(state, f'Reflection & Verification: {len(verified)} verified, {len(rejected)} rejected, {len(inconclusive)} inconclusive'),
    }
