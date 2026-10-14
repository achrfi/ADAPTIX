"""ADAPTIX unified module. Iterasi 6: deterministic two-identity IDOR/BOLA authorization test."""
import time
import httpx as httpx_lib
from src.adaptix.security.scope import endpoint_key
from src.adaptix.workflow.events import log


def idor_test(state):
    """Compare access to the same object between two identities, authorized lab hosts only.
    Runs once per graph invocation regardless of re-plan loop (memoized via idor_findings presence).

    state['idor_scenarios'] items:
      name, base_url, path_template, object_id,
      owner_identity: {name, headers}, other_identity: {name, headers}, method
    """
    if state.get('idor_findings') is not None:
        return {'events': log(state, 'IDOR Test: already executed this run, skipped')}

    scenarios = state.get('idor_scenarios', [])
    hosts = state.get('hosts', [])
    findings = []
    errors = list(state.get('errors', []))

    if not scenarios:
        return {'idor_findings': [], 'events': log(state, 'IDOR Test: skipped; no scenarios configured')}

    with httpx_lib.Client(timeout=10, follow_redirects=False) as client:
        for idx, sc in enumerate(scenarios, start=1):
            base_url = sc.get('base_url', '')
            host = httpx_lib.URL(base_url).host
            if host not in hosts:
                errors.append(f'IDOR scenario "{sc.get("name")}" target not in authorized hosts: {host}')
                continue
            path = sc['path_template'].format(object_id=sc['object_id'])
            url = base_url.rstrip('/') + path
            method = sc.get('method', 'GET')

            try:
                owner_resp = client.request(method, url, headers=sc['owner_identity'].get('headers', {}))
                other_resp = client.request(method, url, headers=sc['other_identity'].get('headers', {}))
            except httpx_lib.HTTPError as exc:
                errors.append(f'IDOR scenario "{sc.get("name")}" request failed: {exc}')
                continue

            owner_ok = 200 <= owner_resp.status_code < 300
            other_denied = other_resp.status_code in (401, 403, 404)
            other_same_as_owner = (
                other_resp.status_code == owner_resp.status_code
                and other_resp.text.strip() == owner_resp.text.strip()
                and owner_ok
            )

            evidence = {
                'evidence_id': f'EV-IDOR-{idx:03d}',
                'source_tool': 'idor_test',
                'target': url,
                'endpoint_key': endpoint_key(url),
                'timestamp': int(time.time()),
                'observation_type': 'authorization',
                'scenario': sc.get('name', url),
                'owner_identity': sc['owner_identity'].get('name'),
                'other_identity': sc['other_identity'].get('name'),
                'owner_status': owner_resp.status_code,
                'other_status': other_resp.status_code,
                'expected_behavior': 'other identity denied (401/403/404) while owner succeeds',
            }

            if owner_ok and other_same_as_owner:
                evidence['verification_status'] = 'verified'
                evidence['confidence'] = 'high'
                evidence['reason'] = (
                    f'{sc["other_identity"].get("name")} accessed object owned by '
                    f'{sc["owner_identity"].get("name")} with identical response (status {other_resp.status_code})'
                )
            elif owner_ok and other_denied:
                evidence['verification_status'] = 'rejected'
                evidence['reason'] = 'authorization correctly enforced; access denied as expected'
            else:
                evidence['verification_status'] = 'inconclusive'
                evidence['reason'] = (
                    f'owner request did not succeed as expected (status {owner_resp.status_code}); '
                    'cannot determine authorization outcome'
                )

            findings.append(evidence)

    return {
        'idor_findings': findings,
        'errors': errors,
        'events': log(state, f'IDOR Test: {len(findings)} scenario(s) evaluated'),
    }
