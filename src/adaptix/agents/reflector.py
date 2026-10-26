"""Evidence triage; server reachability never confirms a vulnerability."""
import time
from urllib.parse import urlsplit, parse_qsl, quote
from src.adaptix.security.scope import endpoint_key
from src.adaptix.workflow.events import log
# Evidence bases that close their own loop against a stored trace. Each one is
# re-evaluated from the record by its contract, so promotion needs no model input.
ORACLE_BASES = ('boolean_injection', 'differential_injection', 'browser_execution')

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


# Status precedence when two records describe the same vulnerability. Merging must
# never *raise* a status: an inconclusive entry stays inconclusive even when a
# signature-based finding exists for the same endpoint.
_STATUS_RANK = {'confirmed': 4, 'verified': 3, 'scanner_matched': 2,
                'inconclusive': 1, 'rejected': 0}
_SEVERITY_RANK = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0}


def _report_identity(entry):
    """Identity of a reported finding: endpoint, parameter, and the payload that proved it.

    Measured defect this closes: `result['findings']` was assigned `web_findings` alone,
    and `build_findings()` can only synthesize from `probe_traces`. Browser XSS, BOLA and
    UNION extraction never write a probe trace, so five verified findings reached the
    report as one. Identity is the evidence's identity, not the record's container.
    """
    evidence = entry.get('verification_evidence') or {}
    reproduction = entry.get('reproduction') or {}
    url = entry.get('target') or entry.get('url') or reproduction.get('url') or ''
    # endpoint_key keeps the query string, so two payloads on one parameter looked like
    # two endpoints (measured: three UNION rows for one vulnerability). Locate by path.
    path = endpoint_key(url)[:4] if endpoint_key(url) else None
    observation = entry.get('actual_observation') or {}
    parameter = (entry.get('parameter') or reproduction.get('parameter')
                 or evidence.get('parameter')
                 or (observation.get('parameter') if isinstance(observation, dict) else '')
                 or '')
    if not parameter:
        parsed = urlsplit(url)
        query = parsed.query or parsed.fragment.partition('?')[2]
        parameter = ','.join(sorted(key for key, _ in parse_qsl(query, keep_blank_values=True)))
    category = (entry.get('finding_type') or entry.get('category')
                or entry.get('vulnerability_name')
                or evidence.get('signature_category') or '')
    # Payload is evidence, not identity: two payloads proving one class on one parameter
    # are one vulnerability, and the strongest record survives the merge.
    return (path, str(parameter), str(category))


def _parameter_name(url):
    """The injected parameter's name from a URL, ignoring payloads in the query."""
    text = str(url or '')
    parsed = urlsplit(text)
    query = parsed.query or parsed.fragment.partition('?')[2]
    names = sorted(name for name, _value in parse_qsl(query, keep_blank_values=True))
    return ','.join(names)

def _payload_from_url(url, parameter=''):
    """The decoded value a stored reproduction URL sent for the named parameter."""
    parsed = urlsplit(str(url or ''))
    query = parsed.query or parsed.fragment.partition('?')[2]
    pairs = parse_qsl(query, keep_blank_values=True)
    for name, value in pairs:
        if not parameter or name == parameter:
            return value
    return pairs[0][1] if pairs else ''

def _url_with_payload(target, parameter, payload):
    """The exact request URL for an extraction when an older record omitted it."""
    target = str(target or '')
    if not target or not parameter or not payload or '?' in target:
        return target
    return '%s?%s=%s' % (target.split('#', 1)[0], parameter,
                         quote(str(payload), safe=',()/*-'))


def _merge_entry(base, other):
    """Combine two records of the same vulnerability without promoting either one."""
    merged = dict(base)
    for key, value in other.items():
        merged.setdefault(key, value)
    # Severity keeps the highest rank; the status keeps the highest rank WITHOUT
    # turning a rejected or inconclusive record into a verified one, because the
    # buckets are partitioned from the same verified statuses and a merge across
    # them would let a signature upgrade an unproven record.
    if _SEVERITY_RANK.get(str(other.get('severity')), 0) > _SEVERITY_RANK.get(
            str(base.get('severity')), 0):
        merged['severity'] = other.get('severity')
    for key in ('evidence_ref', 'raw_evidence_ref', 'verification_evidence'):
        if not merged.get(key) and other.get(key):
            merged[key] = other.get(key)
    # A proven extraction is the impact behind the class it escalated. Merging the
    # password-hash record into the boolean-detection record of the same endpoint used to
    # drop that impact and report the weaker severity, which read as a plain SQLi match
    # while credentials had actually been read. Carry the impact with the merge.
    if other.get('impact_proven'):
        merged['impact_proven'] = True
        for key in ('impact', 'extracted_classes', 'extracted_sample', 'rows_returned',
                    'evidence_basis', 'source_tool', 'payload', 'url', 'reproduction',
                    'attempts'):
            if other.get(key):
                merged[key] = other[key]
        merged['severity'] = 'critical'
        merged['verification_status'] = 'verified'
    # Report-facing identifiers are preserved so the audit trail still resolves.
    for key in ('finding_id', 'evidence_id', 'reproduction', 'cwe', 'owasp',
                'payload', 'url', 'attempts'):
        if not merged.get(key) and other.get(key):
            merged[key] = other.get(key)
    return merged


def _merge_report_findings(web_findings, bucket_entries):
    """Every finding the run proved, in one list, with one record per vulnerability."""
    merged = {}
    order = []
    # The report states what the run proved. An inconclusive or rejected record stays in
    # its own bucket for the operator to see, but it is not a finding: including it would
    # let a signature alone reach the deliverable (measured: /metrics prometheus-metrics
    # was inconclusive and appeared as a finding row).
    # Scanner matches and inconclusive candidates stay in their own audit buckets.
    # At the end, only an independently verified finding is a finding; a Nuclei
    # template match is the scanner's verdict, not proof from this run.
    reportable = {'confirmed', 'verified'}
    for entry in list(web_findings or []) + [e for e in bucket_entries if isinstance(e, dict)]:
        if not isinstance(entry, dict):
            continue
        if str(entry.get('verification_status') or 'web') not in reportable:
            continue
        identity = _report_identity(entry)
        if identity in merged:
            merged[identity] = _merge_entry(merged[identity], entry)
        else:
            merged[identity] = dict(entry)
            order.append(identity)
    return [merged[identity] for identity in order]


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
    for prior in state.get('verified_findings', []) + state.get('scanner_matched_findings', []):
        if (isinstance(prior, dict) and prior.get('tool_source') == 'nuclei' and prior.get('finding_id')
                and prior.get('verification_status') in ('verified', 'scanner_matched')
                and (prior.get('verification_level') in ('scanner_matched', 'scanner_verified', 'verified')
                     or prior.get('verification_method') == 'nuclei_template_match')):
            findings[('nuclei', prior['finding_id'])] = prior
    # A Nuclei match that the adapter already verified must not reappear below as
    # an unverified candidate: the candidate bucket is for evidence still needing
    # an independent check, not a second copy of an already-verified match.
    verified_nuclei = {(row.get('template_id'), endpoint_key(row.get('target', '')))
                       for row in state.get('verified_findings', []) if isinstance(row, dict)
                       and row.get('tool_source') == 'nuclei'
                       and row.get('verification_method') == 'nuclei_template_match'}

    def add(entry):
        if entry.get('finding_type') == 'broken_object_level_authorization':
            key = ('idor', endpoint_key(entry.get('target', '')),
                   entry.get('owner_identity'), entry.get('other_identity'))
        else:
            evidence = entry.get('verification_evidence') or {}
            identity = (evidence.get('template_id') or evidence.get('evidence_ref')
                        or entry.get('template_id'))
            key = ('candidate', identity, endpoint_key(entry.get('target', '')))
        previous = findings.get(key)
        if previous and previous.get('verification_evidence') and not entry.get('verification_evidence'):
            return
        findings[key] = entry

    for idx, candidate in enumerate(state.get('candidates', []), start=1):
        if (candidate.get('template_id'), endpoint_key(candidate.get('url', ''))) in verified_nuclei:
            continue
        # Inventory observations (technology fingerprints, informational matches)
        # belong to recon_inventory, not to the vulnerability finding buckets.
        if candidate.get('finding_type') == 'service_observation':
            continue
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
        # An IDOR record carries no severity field of its own, so every verified
        # object-level authorization finding reported as "unknown" - a severity the
        # report cannot triage. The class is rated from what the oracle actually
        # proved: a cross-identity read of private data is a broken access control
        # defect (CWE-639), medium by default and high once a verified finding shows
        # the other identity obtained the owner's private field content.
        entry = {**(record or finding), 'source_tool': 'idor_test',
                 'target': finding.get('target', ''),
                 'finding_type': 'broken_object_level_authorization',
                 'verification_evidence': proof,
                 'severity': finding.get('severity') or ('high' if proof else 'medium'),
                 'cwe': finding.get('cwe') or 'CWE-639',
                 'owasp': finding.get('owasp') or 'A01:2021 Broken Access Control'}
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

    # A capability that executed an escalation proves its class directly. Those records
    # live in `injection_findings`, and this function rebuilds `verified_findings` from the
    # candidate and oracle buckets only - so a run that extracted a real password hash
    # through the injection reported the plain SQLi match and no impact. Fold them in here:
    # the report reads one list, and every proven class must reach it by that one path.
    for index, row in enumerate(state.get('injection_findings') or [], start=1):
        if not isinstance(row, dict):
            continue
        if str(row.get('verification_status') or '') not in ('verified', 'confirmed'):
            continue
        if not row.get('impact_proven'):
            continue
        category = str(row.get('class') or row.get('finding_type') or 'sql_injection')
        parameter = str(row.get('parameter') or '')
        payload = str(row.get('payload') or '')
        proof_url = str(row.get('url') or _url_with_payload(row.get('target', ''),
                                                            parameter, payload))
        reproduction = row.get('reproduction') if isinstance(row.get('reproduction'), dict) else {}
        add({
            'evidence_id': f'EV-EXTRACT-{index:03d}',
            'source_tool': 'union_extract',
            'target': row.get('target', ''),
            'url': proof_url,
            'timestamp': int(time.time()),
            'template_id': 'adaptix-extraction-' + (parameter or 'q'),
            'severity': row.get('severity') or 'critical',
            'finding_type': category, 'category': category,
            'parameter': parameter,
            'payload': payload,
            'reproduction': reproduction or {'method': 'GET', 'url': proof_url,
                                             'parameter': parameter, 'payload': payload},
            'actual_observation': {'parameter': parameter,
                                   'url': proof_url,
                                   'rows_returned': row.get('rows_returned'),
                                   'columns': row.get('columns')},
            'verification_evidence': None, 'confidence': 'supported',
            'web_finding': None,
            'impact_proven': True,
            'impact': row.get('impact'),
            'extracted_classes': list(row.get('extracted_classes') or []),
            'extracted_sample': list(row.get('extracted_sample') or []),
            'rows_returned': row.get('rows_returned'),
            'evidence_basis': row.get('evidence_basis') or 'union_extraction_executed',
            'verification_status': 'verified',
            'reason': 'a deterministic extraction executed through the injection returned '
                      'rows from the application database',
        })

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
        if record is None or record.get('verification_basis') not in ORACLE_BASES:
            continue
        category = BASIS_CATEGORIES.get(record['verification_basis'])
        parameter = _parameter_name(record.get('url', ''))
        payload = _payload_from_url(record.get('url', ''), parameter)
        entry = {
            'evidence_id': f'EV-ORACLE-{index:03d}',
            'source_tool': {'private_object_access': 'authorization_probe',
                            'differential_injection': 'injection_probe',
                            'boolean_injection': 'injection_probe',
                            'browser_execution': 'script_probe'}.get(
                                record['verification_basis'], 'http_request'),
            'target': record['url'], 'url': record['url'], 'timestamp': int(time.time()),
            'template_id': record['template_id'],
            'severity': 'high' if category == 'sql_injection' else 'medium',
            'finding_type': category, 'category': category,
            'payload': payload,
            'reproduction': {'method': record.get('method'), 'url': record['url'],
                             'parameter': parameter, 'payload': payload},
            # Measured: this field carried the whole URL, so the finding's identity became
            # (path, full-URL, class) and the same vulnerability recorded by the extraction
            # as (path, 'q', class) never merged - two rows for one hole. The field means the
            # parameter's name, so derive the name.
            'actual_observation': {'method': record.get('method'),
                                   'parameter': parameter,
                                   'url': str(record.get('url', ''))[:160]},
            'parameter': parameter,
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
        finding_url = str(finding.get('target') or finding.get('url') or '')
        finding_parameter = str(finding.get('parameter') or '')
        finding_payload = str(finding.get('payload') or _payload_from_url(
            finding_url, finding_parameter))
        entry = {
            'evidence_id': f'EV-WEB-{index:03d}', 'source_tool': 'http_request',
            'target': finding_url, 'url': finding_url, 'timestamp': int(time.time()),
            'template_id': 'adaptix-' + str(finding.get('category')), 'severity': finding.get('severity'),
            'finding_type': finding.get('category'), 'category': finding.get('category'),
            'parameter': finding_parameter, 'payload': finding_payload,
            'actual_observation': {'observations': finding.get('observations', []),
                                   'method': finding.get('method'), 'parameter': finding_parameter,
                                   'url': finding_url},
            'verification_evidence': proof or finding.get('reproduction'),
            'confidence': 'supported' if status == 'confirmed' else 'unconfirmed',
            'reason': finding.get('severity_rationale'), 'report_status': REPORT_STATUS.get(status, status.upper()),
            'web_finding': finding,
            'verification_status': {'confirmed': 'verified', 'false_positive': 'rejected'}.get(status, 'inconclusive'),
        }
        add(entry)

    result = {name: [entry for entry in findings.values() if entry['verification_status'] == status]
              for name, status in (('verified_findings', 'verified'),
                                   ('scanner_matched_findings', 'scanner_matched'),
                                   ('rejected_findings', 'rejected'),
                                   ('inconclusive_findings', 'inconclusive'))}
    result['findings'] = _merge_report_findings(web_findings, findings.values())
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
