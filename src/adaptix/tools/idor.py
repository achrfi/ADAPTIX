"""ADAPTIX unified module. Iterasi 6: deterministic two-identity IDOR/BOLA authorization test."""
import time
<<<<<<< HEAD
import hashlib
import secrets
import json
from urllib.parse import quote
from src.adaptix.evidence.storage import artifact_path, save_text
import httpx as httpx_lib
from src.adaptix.security.scope import endpoint_key, allowed_url
from src.adaptix.security.transport import bind_url
from src.adaptix.config import config
from src.adaptix.security.ports import ports_for_state
from src.adaptix.workflow.budget import tool_budget_available, record_tool_call, tool_timeout
from src.adaptix.workflow.events import log
from src.adaptix.evidence.sanitize import sanitize, response_record, SENSITIVE
from src.adaptix.evidence.verification import write_verification_record
from src.adaptix.security.authorization import _key
=======
import httpx as httpx_lib
from src.adaptix.security.scope import endpoint_key
from src.adaptix.workflow.events import log
>>>>>>> origin/main


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
<<<<<<< HEAD
    execution_metrics = dict(state.get("execution_metrics", {}))
    errors = list(state.get('errors', []))
    raw_bytes = int(state.get('raw_bytes', 0))
=======
    errors = list(state.get('errors', []))
>>>>>>> origin/main

    if not scenarios:
        return {'idor_findings': [], 'events': log(state, 'IDOR Test: skipped; no scenarios configured')}

<<<<<<< HEAD
    with httpx_lib.Client(timeout=tool_timeout(state, 10), follow_redirects=False, trust_env=False) as client:
        for idx, sc in enumerate(scenarios, start=1):
            base_url = sc.get('base_url', '')
            path = sc['path_template'].format(object_id=quote(str(sc['object_id']), safe=''))
            url = base_url.rstrip('/') + path
            method = sc.get('method', 'GET')

            ports = set(ports_for_state(state, config('scope.yaml')['limits']))
            if method != 'GET' or not allowed_url(url, hosts, ports, state.get('scope_aliases'), state.get('scope_networks')):
                errors.append('IDOR policy rejected method or endpoint not in authorized hosts')
                continue
            # Reserve both requests before starting an identity comparison.
            used = int(execution_metrics.get('tool_calls_used', 0))
            if used + 2 > int(state.get('tool_call_budget', 20)):
                errors.append('IDOR: insufficient request budget')
                break
            execution_metrics = record_tool_call({**state, 'execution_metrics': execution_metrics}, 'idor')
            execution_metrics = record_tool_call({**state, 'execution_metrics': execution_metrics}, 'idor')
            actual_url, host_headers, sni = bind_url(url, state)
            extensions = {'sni_hostname': sni} if sni else {}
            try:
                owner_resp = client.request(method, actual_url, headers={**sc['owner_identity'].get('headers', {}), **host_headers}, extensions=extensions)
                other_resp = client.request(method, actual_url, headers={**sc['other_identity'].get('headers', {}), **host_headers}, extensions=extensions)
=======
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
>>>>>>> origin/main
            except httpx_lib.HTTPError as exc:
                errors.append(f'IDOR scenario "{sc.get("name")}" request failed: {exc}')
                continue

            owner_ok = 200 <= owner_resp.status_code < 300
            other_denied = other_resp.status_code in (401, 403, 404)
            other_same_as_owner = (
                other_resp.status_code == owner_resp.status_code
<<<<<<< HEAD
                and other_resp.text == owner_resp.text
                and owner_ok
            )
            owner, other = sc['owner_identity'], sc['other_identity']
            truth = sc.get('ground_truth', {})
            owner_auth = {k.lower(): v for k, v in owner.get('headers', {}).items() if SENSITIVE.fullmatch(k)}
            other_auth = {k.lower(): v for k, v in other.get('headers', {}).items() if SENSITIVE.fullmatch(k)}
            valid_fixture = (truth.get('private') is True and truth.get('identities_valid') is True
                             and truth.get('owner') == owner.get('name')
                             and str(truth.get('object_id')) == str(sc['object_id'])
                             and owner.get('name') and other.get('name') and owner['name'] != other['name']
                             and bool(owner_auth) and bool(other_auth) and owner_auth != other_auth)
            secret_values = list(owner.get('headers', {}).values()) + list(other.get('headers', {}).values())
            owner_trace, other_trace = response_record(owner_resp, secret_values), response_record(other_resp, secret_values)
            raw_bytes += len(owner_resp.text.encode()) + len(other_resp.text.encode())
=======
                and other_resp.text.strip() == owner_resp.text.strip()
                and owner_ok
            )
>>>>>>> origin/main

            evidence = {
                'evidence_id': f'EV-IDOR-{idx:03d}',
                'source_tool': 'idor_test',
                'target': url,
                'endpoint_key': endpoint_key(url),
                'timestamp': int(time.time()),
                'observation_type': 'authorization',
                'scenario': sc.get('name', url),
<<<<<<< HEAD
                'object_id': str(sc['object_id']),
=======
>>>>>>> origin/main
                'owner_identity': sc['owner_identity'].get('name'),
                'other_identity': sc['other_identity'].get('name'),
                'owner_status': owner_resp.status_code,
                'other_status': other_resp.status_code,
<<<<<<< HEAD
                'owner_response_sha256': hashlib.sha256(owner_resp.text.encode()).hexdigest(),
                'other_response_sha256': hashlib.sha256(other_resp.text.encode()).hexdigest(),
                'expected_behavior': 'other identity denied (401/403/404) while owner succeeds',
                'ground_truth': truth,
                'assessment_basis': 'operator-supplied lab ownership and valid-account assertion',
                'fixture_validated': bool(valid_fixture),
                'steps': ['GET the selected object as its owner', 'GET the same object as the other identity',
                          'Compare status and response; evaluate against private-object ground truth'],
                'requests': [{'identity': identity.get('name'), 'method': method, 'url': sanitize(url),
                              'headers': sanitize(identity.get('headers', {}), secret_values)}
                             for identity in (owner, other)],
                'responses': [owner_trace, other_trace],
                'actual_behavior': {'owner_status': owner_resp.status_code, 'other_status': other_resp.status_code,
                                    'identical_body': other_same_as_owner},
                'response_diff': {'status_changed': owner_resp.status_code != other_resp.status_code,
                                  'body_changed': owner_trace['body_sha256'] != other_trace['body_sha256']},
                'session_context': {'owner': owner.get('name'), 'other': other.get('name'),
                                    'credential_values_stored': False},
            }

            if owner_ok and other_same_as_owner and valid_fixture:
                evidence['verification_status'] = 'verified'
                evidence['confidence'] = 'supported'
=======
                'expected_behavior': 'other identity denied (401/403/404) while owner succeeds',
            }

            if owner_ok and other_same_as_owner:
                evidence['verification_status'] = 'verified'
                evidence['confidence'] = 'high'
>>>>>>> origin/main
                evidence['reason'] = (
                    f'{sc["other_identity"].get("name")} accessed object owned by '
                    f'{sc["owner_identity"].get("name")} with identical response (status {other_resp.status_code})'
                )
            elif owner_ok and other_denied:
                evidence['verification_status'] = 'rejected'
                evidence['reason'] = 'authorization correctly enforced; access denied as expected'
            else:
                evidence['verification_status'] = 'inconclusive'
<<<<<<< HEAD
                evidence['reason'] = ('Owner/private-object ground truth or distinct valid identities missing; '
                                      'equal responses alone do not prove IDOR' if not valid_fixture else
                                      f'Responses do not establish the expected authorization result (owner={owner_resp.status_code}, other={other_resp.status_code})')

            evidence_state = {**state, 'run_id': state.get('run_id') or secrets.token_hex(6)}
            identity_key = json.dumps([sc.get('name'), owner.get('name'), other.get('name')])
            evidence['template_id'] = 'adaptix-idor-' + hashlib.sha256(identity_key.encode()).hexdigest()[:16]
            evidence['run_id'] = evidence_state['run_id']
            if valid_fixture and evidence['verification_status'] in ('verified', 'rejected'):
                _key(create=True)
                evidence['verification_evidence'] = write_verification_record(evidence_state, {
                    **evidence, 'url': url, 'verification_method': 'deterministic_replay',
                    'verification_basis': 'private_object_access'})
            evidence_path = artifact_path(evidence_state, 'idor', url + '#' + sc.get('name', str(idx)), 'json')
            evidence = sanitize(evidence, secret_values)
            save_text(evidence_path, json.dumps(evidence, ensure_ascii=False))
            evidence['evidence_ref'] = str(evidence_path)
            findings.append(evidence)

    return {
        'execution_metrics': execution_metrics,
        'raw_bytes': raw_bytes,
=======
                evidence['reason'] = (
                    f'owner request did not succeed as expected (status {owner_resp.status_code}); '
                    'cannot determine authorization outcome'
                )

            findings.append(evidence)

    return {
>>>>>>> origin/main
        'idor_findings': findings,
        'errors': errors,
        'events': log(state, f'IDOR Test: {len(findings)} scenario(s) evaluated'),
    }
