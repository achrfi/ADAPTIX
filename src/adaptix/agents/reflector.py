"""Evidence triage; server reachability never confirms a vulnerability."""
import time
from src.adaptix.security.scope import endpoint_key
from src.adaptix.workflow.events import log
from src.adaptix.evidence.verification import BASIS_CATEGORIES, load_valid_proof
from src.adaptix.evidence.web_signatures import build_findings, REPORT_STATUS

# External (future) vulnerability-specific verifier may supply explicit replay results.
# Untrusted Nuclei severity and HTTP status never promote a candidate by themselves.


def endpoint_path_key(url):
    """Endpoint identity without the query, for attaching a probe to its finding.

    A finding is reported against the endpoint; the probe payload lives in the query,
    so matching on the full URL would never bind a signed record to its finding.
    """
    key = endpoint_key(url or '')
    return key[:4] if key else None


def _proof_for(candidate, proofs, run_id=None):
    for proof in proofs:
        if (proof.get('template_id') == candidate.get('template_id')
                and endpoint_key(proof.get('url', '')) == endpoint_key(candidate.get('url', ''))
                and proof.get('verification_method') in ('deterministic_replay', 'manual_review')
                and proof.get('evidence_ref')
                and proof.get('result') in ('confirmed', 'refuted')):
            record = load_valid_proof(candidate, proof, run_id)
            if record is not None:
                return proof, record
    return None, None


def _web_proof_for(finding, proofs, run_id=None):
    """Authenticate a replay record that answers this synthesized web finding.

    The record is matched by endpoint and by the signature category its contract
    decided; the finding's category must be the one the record proves.
    """
    for proof in proofs:
        if (proof.get('verification_method') != 'deterministic_replay'
                or proof.get('result') not in ('confirmed', 'refuted')
                or not proof.get('evidence_ref')
                or endpoint_path_key(proof.get('url', '')) != endpoint_path_key(finding.get('target', ''))):
            continue
        candidate = {'template_id': proof.get('template_id'), 'url': proof.get('url', '')}
        record = load_valid_proof(candidate, proof, run_id)
        if record is None:
            continue
        if record.get('signature_category') == finding.get('category'):
            return proof
    return None


def _private_object_evidence(record):
    """Two distinct identities plus a decisive ownership response pattern, or None.

    A manual-review label without an identity trace is not authorization proof, and
    the promotion must never index into a missing/partial ``requests`` list.
    """
    if not record or record.get('verification_basis') != 'private_object_access':
        return None
    requests = [r for r in (record.get('requests') or []) if isinstance(r, dict)]
    if len(requests) < 2:
        return None
    owner, other = requests[0].get('identity'), requests[1].get('identity')
    if not owner or not other or owner == other:
        return None
    responses = record.get('responses') or []
    if len(responses) >= 2:
        owner_response, other_response = responses[0], responses[1]
        owner_ok = isinstance(owner_response.get('status_code'), int) and 200 <= owner_response['status_code'] < 300
        other_blocked = other_response.get('status_code') in (401, 403, 404)
        same_body = (owner_response.get('status_code') == other_response.get('status_code')
                     and owner_response.get('body_sha256') == other_response.get('body_sha256'))
        if not owner_ok or not (other_blocked or same_body):
            return None
    return {'owner_identity': owner, 'other_identity': other}


def collect_findings(state):
    """Unify scanner and IDOR results; authenticate proof and count each assessment once."""
    http_by_url = {endpoint_key(item.get('url', '')): item for item in state.get('http_services', [])}
    findings = {}
    # Nuclei verdicts register before any model pass and by the engine's own
    # matching authority. collect_findings rebuilds buckets from candidates and
    # proofs, which know nothing of the adapter's rows, so scanner-verified
    # entries are seeded first and are never dropped or re-judged here; the
    # signed 'nuclei' key keeps them distinct from every independently verified
    # record instead of merging with it.
    for prior in state.get('verified_findings', []):
        if isinstance(prior, dict) and prior.get('verification_level') == 'scanner_verified' \
                and prior.get('tool_source') == 'nuclei' and prior.get('finding_id'):
            findings[('nuclei', prior['finding_id'])] = prior

    def add(entry):
        if entry.get('finding_type') == 'broken_object_level_authorization':
            key = ('idor', endpoint_key(entry.get('target', '')),
                   entry.get('owner_identity'), entry.get('other_identity'))
        else:
            key = ('candidate', entry.get('template_id'), endpoint_key(entry.get('target', '')))
        previous = findings.get(key)
        if previous and previous.get('verification_evidence') and not entry.get('verification_evidence'):
            return
        findings[key] = entry

    for idx, candidate in enumerate(state.get('candidates', []), start=1):
        observation = http_by_url.get(endpoint_key(candidate.get('url', '')))
        proof, record = _proof_for(candidate, state.get('verification_evidence', []), state.get('run_id'))
        private = _private_object_evidence(record)
        idor_claim = candidate.get('finding_type') == 'broken_object_level_authorization'
        category = (candidate.get('finding_type') or (record or {}).get('signature_category')
                    or (BASIS_CATEGORIES.get((record or {}).get('verification_basis')) if record else None))
        entry = {
            'evidence_id': f'EV-{idx:03d}', 'source_tool': candidate.get('source_tool', 'nuclei'),
            'target': candidate.get('url', ''), 'timestamp': int(time.time()),
            'template_id': candidate.get('template_id', ''),
            'severity': candidate.get('severity', 'info'),
            'finding_type': category, 'category': category,
            'actual_observation': ({'status_code': observation.get('status_code'),
                                    'title': observation.get('title', '')} if observation else None),
            'verification_evidence': proof, 'confidence': 'unconfirmed',
        }
        if candidate.get('finding_type') == 'service_reachability' or candidate.get('template_id') == 'adaptix-http-baseline':
            entry.update(verification_status='rejected', reason='reachability baseline is not a vulnerability')
        elif proof and proof['result'] == 'confirmed' and idor_claim and private is None:
            # An authorization claim cannot be verified by a review label alone; it
            # needs two distinct identities and a decisive ownership response.
            entry.update(verification_status='inconclusive', confidence='unconfirmed',
                         reason='Authorization claim lacks two-identity ownership evidence; a review label alone cannot verify it')
        elif proof and proof['result'] == 'confirmed':
            entry.update(verification_status='verified', confidence='supported',
                         reason='vulnerability-specific replay/review evidence provided')
        elif proof and proof['result'] == 'refuted':
            entry.update(verification_status='rejected', reason='vulnerability-specific check refuted candidate')
        else:
            entry.update(verification_status='inconclusive',
                         reason='HTTP status/severity do not prove or disprove a vulnerability; independent check needed')
        if private:
            entry.update(finding_type='broken_object_level_authorization', **private)
        add(entry)

    for finding in state.get('idor_findings', []):
        if not isinstance(finding, dict):
            continue
        candidate = {'template_id': finding.get('template_id'), 'url': finding.get('target', '')}
        proof = finding.get('verification_evidence')
        proof, record = _proof_for(candidate, [proof] if isinstance(proof, dict) else [], state.get('run_id'))
        entry = {**(record or finding), 'source_tool': 'idor_test',
                 'target': finding.get('target', ''),
                 'finding_type': 'broken_object_level_authorization',
                 'verification_evidence': proof, 'severity': finding.get('severity', 'unknown')}
        if record:
            entry.update(target=record['url'], evidence_ref=proof['evidence_ref'],
                         raw_evidence_ref=finding.get('evidence_ref'),
                         verification_status='verified' if proof['result'] == 'confirmed' else 'rejected',
                         confidence='supported')
        else:
            entry.update(verification_status='inconclusive', confidence='unconfirmed')
            if finding.get('verification_status') != 'inconclusive':
                entry['reason'] = 'IDOR proof missing, invalid or from another run; rerun the two-identity check'
        add(entry)

    # A deterministic oracle closes its own loop: the boolean companions and the
    # browser session are struck against the same endpoint the probe describes, so
    # an authenticated record of that contract *is* decisive evidence. A record
    # that matches no candidate or web-finding row promotes its own finding here;
    # the record, not a label, does the verifying.
    oracle_evidence = []
    for index, row in enumerate(state.get('verification_evidence', []), start=1):
        if not isinstance(row, dict) or row.get('result') not in ('confirmed', 'refuted'):
            continue
        candidate = {'template_id': row.get('template_id'), 'url': row.get('url', '')}
        record = load_valid_proof(candidate, row, state.get('run_id'))
        if record is None or record.get('verification_basis') not in ('boolean_injection', 'browser_execution'):
            continue
        category = BASIS_CATEGORIES.get(record['verification_basis'])
        entry = {
            'evidence_id': f'EV-ORACLE-{index:03d}', 'source_tool': 'http_request',
            'target': record['url'], 'timestamp': int(time.time()),
            'template_id': record['template_id'],
            'severity': 'high' if category == 'sql_injection' else 'medium',
            'finding_type': category, 'category': category,
            'actual_observation': {'method': record.get('method'),
                                   'parameter': str(record.get('url', ''))[:120]},
            'verification_evidence': row, 'evidence_ref': row.get('evidence_ref'),
            'confidence': 'supported' if row['result'] == 'confirmed' else 'unconfirmed',
            'web_finding': None,
            'verification_status': {'confirmed': 'verified', 'refuted': 'rejected'}[row['result']],
            'reason': ('boolean behavior difference reproduced deterministically on the same endpoint'
                       if record['verification_basis'] == 'boolean_injection' and row['result'] == 'confirmed'
                       else 'browser dialog round trip reproduced deterministically on the same endpoint'
                       if row['result'] == 'confirmed' else 'deterministic control refuted the payload'),
        }
        add(entry)

    web_findings = build_findings(state)
    for index, finding in enumerate(web_findings, start=1):
        # A signature and a clean control are a hypothesis, not proof: a synthesized web
        # finding is verified only when an authenticated replay record answers it. Without
        # that record the finding is inconclusive, never 'confirmed' from the label alone.
        proof = _web_proof_for(finding, state.get('verification_evidence', []), state.get('run_id'))
        if proof:
            status = 'confirmed' if proof['result'] == 'confirmed' else 'false_positive'
        else:
            status = 'inconclusive'
        entry = {
            'evidence_id': f'EV-WEB-{index:03d}', 'source_tool': 'http_request',
            'target': finding.get('target'), 'timestamp': int(time.time()),
            'template_id': 'adaptix-' + str(finding.get('category')), 'severity': finding.get('severity'),
            'finding_type': finding.get('category'), 'category': finding.get('category'),
            'actual_observation': {'observations': finding.get('observations', []),
                                   'method': finding.get('method'), 'parameter': finding.get('parameter')},
            'verification_evidence': proof or finding.get('reproduction'),
            'confidence': 'supported' if status == 'confirmed' else 'unconfirmed',
            'reason': finding.get('severity_rationale'), 'report_status': REPORT_STATUS.get(status, status.upper()),
            'web_finding': finding,
            'verification_status': {'confirmed': 'verified', 'false_positive': 'rejected'}.get(status, 'inconclusive'),
        }
        add(entry)

    result = {name: [entry for entry in findings.values() if entry['verification_status'] == status]
              for name, status in (('verified_findings', 'verified'), ('rejected_findings', 'rejected'),
                                   ('inconclusive_findings', 'inconclusive'))}
    result['findings'] = web_findings
    return result


def reflection_verification(state):
    from src.adaptix.agents.hypotheses import update_hypotheses
    from src.adaptix.agents.progress import stagnation_report
    groups = collect_findings(state)
    verified, rejected, inconclusive = (groups[name] for name in
                                        ('verified_findings', 'rejected_findings', 'inconclusive_findings'))
    stagnation = stagnation_report(state)
    consecutive = stagnation['consecutive_no_gain']
    blocked = [{'tool': row.get('tool'), 'target': row.get('target'),
                'code': row.get('code', ''), 'kind': row.get('kind', ''),
                'missing': row.get('missing', [])[:3]}
               for row in state.get('rejected_actions', [])[-6:]]
    completed = [{'tool': row.get('tool'), 'target': row.get('target')}
                 for row in state.get('attempted_actions', [])[-6:]]
    unfinished = [row.get('target') for row in inconclusive]
    # Planning failures are kept apart from tool/security errors: a schema or no-decision
    # failure never describes anything about the target.
    planning_failures = [str(row) for row in state.get('errors', []) if str(row).startswith('Planning pass')]
    planning = {'passes': stagnation['planning_passes'],
                'zero_action_plans': stagnation['zero_action_plans'],
                'consecutive_empty_plans': stagnation['consecutive_empty_plans'],
                'consecutive_schema_failures': stagnation['consecutive_schema_failures']}
    if planning['consecutive_empty_plans']:
        guidance = ('The planner returned no executable action while authorized alternatives remain ('
                    + str(planning['consecutive_empty_plans']) +
                    ' in a row). Use policy_feedback alternatives: propose an eligible (tool, target) pair the '
                    'evidence supports, state the specific evidence still needed, or record the concrete limitation. '
                    'A formatting or planning error is not a security result.')
    elif planning['consecutive_schema_failures']:
        guidance = ('The model decision failed schema validation; correct the reported fields and re-propose the '
                    'intended action with valid types and ranges. This is a formatting failure, never a finding.')
    elif consecutive >= 2:
        guidance = ('Repeated actions added no measured progress (' + str(consecutive) +
                    ' in a row). Change what the next action is evidence about - a different endpoint, a different '
                    'question, or a different hypothesis - or stop with the recorded limitation.')
    elif consecutive == 1:
        guidance = ('The last action added no measured progress; an identical or parameter-only repeat of it will '
                    'not either. Change the evidence source or the question.')
    elif blocked:
        guidance = ('Some actions were not executed. Each blocked action records which prerequisite was missing; '
                    'choose an action whose prerequisites the run already satisfies instead of repeating one.')
    else:
        guidance = 'Choose the next action from current evidence; verify uncertainty or stop with limitations.'
    return {
        'hypotheses': update_hypotheses(state),
        'hypothesis_diagnostics': state.get('planner_metrics', {}).get('hypothesis_diagnostics', {}),
        'reflection': {'progress': len(state.get('attempted_actions', [])),
                       'uncertainty': unfinished,
                       'errors': state.get('errors', [])[-8:],
                       'last_action': state.get('attempted_actions', [])[-1:],
                       'last_outcome': stagnation['recent'][-1:],
                       'consecutive_no_gain': consecutive,
                       'policy_feedback': state.get('policy_feedback', []),
                       'blocked_actions': blocked,
                       'completed_actions': completed,
                       'planning': planning,
                       'planning_failures': planning_failures[-6:],
                       'guidance': guidance},
        **groups,
        'events': log(state, f'Reflection: {len(verified)} verified, {len(rejected)} non-findings/refuted, '
                             f'{len(inconclusive)} inconclusive'),
    }
