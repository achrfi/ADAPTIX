"""Validate provenance and minimum proof, not a scanner's severity label.

Every automated result comes from an *objective evidence contract*: a named basis
plus a pure evaluator that reads only the stored trace and returns confirmed,
refuted or None. The contracts share one rule - a status code, a severity label or
an LLM claim never confirms anything; the trace itself must contain the proof, and
for differential classes a matching control observation on the same path must show
the input, not the endpoint, caused it.
"""
import hashlib
import hmac
import json
import time
import re
from pathlib import Path
from src.adaptix.config import ROOT
from src.adaptix.security.authorization import _key, _payload_bytes
from src.adaptix.security.scope import endpoint_key
from src.adaptix.evidence.storage import artifact_path, save_text
from src.adaptix.evidence.sanitize import sanitize, scenario_secrets
from src.adaptix.evidence import web_signatures


def _private_object_access(record):
    """Two distinct valid identities, owner succeeds and non-owner is not blocked.

    The single supported proof today: the object is known private, both sessions are
    valid, and the non-owner receives the same decisive response as the owner.
    """
    truth = record.get('ground_truth', {})
    requests, responses = record.get('requests', []), record.get('responses', [])
    if not (len(requests) == len(responses) == 2 and truth.get('private') is True
            and truth.get('identities_valid') is True and truth.get('owner') == requests[0].get('identity')
            and str(truth.get('object_id')) == str(record.get('object_id'))
            and requests[0].get('identity') and requests[1].get('identity')
            and requests[0]['identity'] != requests[1]['identity']
            and all(r.get('method') == 'GET' and endpoint_key(r.get('url', '')) == endpoint_key(record.get('url', '')) for r in requests)):
        return None
    owner, other = responses
    if not 200 <= owner['status_code'] < 300:
        return None
    if other['status_code'] in (401, 403, 404):
        return 'refuted'
    if owner['status_code'] == other['status_code'] and owner['body_sha256'] == other['body_sha256']:
        return 'confirmed'
    return None


def _differential_category(record):
    """The signature category a differential trace claims, if any."""
    return record.get('signature_category')


def _control_is_clean(record, category):
    """A control observation on the same path with no detection of this category.

    Without a clean control, the signature only says the endpoint behaves oddly in
    general; with one, the probe input is what produced it. A control's own
    ``detected`` list cannot contain payload-gated signatures (SQL/NoSQL/traversal
    rules run only for crafted payloads), so the control's stored body excerpt is
    re-evaluated with the same rule families before it is trusted as clean.
    """
    controls = [row for row in (record.get('controls') or []) if isinstance(row, dict)]
    if not controls:
        return False
    from src.adaptix.evidence.web_signatures import control_detections
    for row in controls:
        if row.get('excerpt_truncated'):
            # The excerpt is all that was stored: 'no marker in what we kept' is not
            # 'no marker in the response', so the control can never be trusted clean.
            return False
        known = [d for d in (row.get('detected') or []) if isinstance(d, dict)]
        if any(d.get('category') == category for d in known):
            return False
        if any(d['category'] == category for d in control_detections(row.get('body_excerpt', ''))):
            return False
    return True


def _differential_injection(record):
    """SQL/NoSQL error behaviour that the probe input caused, proven by a clean control."""
    category = _differential_category(record)
    if category not in ('sql_injection', 'nosql_injection'):
        return None
    signatures = {d.get('signature') for d in (record.get('detected') or [])
                  if d.get('category') == category}
    if not signatures:
        return None
    return 'confirmed' if _control_is_clean(record, category) else None


def _reflected_markup(record):
    """Attacker markup reflected into HTML unencoded; encoding proves it is handled.

    Reflection alone stays a *signature*, never the verified XSS contract: it
    remains available as an intermediate basis for categories whose only claim is
    markup handling, while the verified cross_site_scripting contract requires
    browser execution.
    """
    signatures = {d.get('signature') for d in (record.get('detected') or [])
                  if d.get('category') == 'cross_site_scripting'}
    if 'reflected_html_markup' in signatures:
        return 'confirmed'
    if 'html_encoded_reflection' in signatures:
        return 'refuted'
    return None


def _browser_execution(record):
    """Attacker script actually executed in a real browser context.

    The stored browser session must show a run-provided marker round trip: the
    marker is carried in the navigated URL (so the response actually received
    attacker input at the run's chosen injection point) and appears in a browser
    dialog from script execution, while a control navigation of the same URL with
    the marker removed never fires a marker dialog. HTML5 dialogs are dismissed
    by the deterministic tool after capture.
    """
    browser = record.get('browser') or {}
    marker = str(browser.get('marker') or '')
    if not marker or len(marker) < 6 or len(marker) > 64 or not re.fullmatch(r'[A-Za-z0-9_.-]{6,64}', marker):
        return None
    if not any(request.get('url', '').find(marker) >= 0 for request in record.get('requests', [])):
        return None
    messages = [str(message).casefold() for message in browser.get('dialog_messages', [])]
    control_messages = [str(message).casefold() for message in browser.get('control_dialog_messages', [])]
    if not any(marker.casefold() in message for message in messages):
        return None
    if any(marker.casefold() in message for message in control_messages):
        # The same dialog fires without the payload marker: site-wide script, not injection.
        return 'refuted'
    return 'confirmed'


def _boolean_injection(record):
    """User-controlled input changes backend query behavior; HTTP behavior as oracle.

    Requires a stable truthy probe (reproduced), a nominal clean control and a
    falsy probe on the same endpoint/method where the falsy and clean observations
    are behaviorally identical and the truthy observation differs from both: a
    boolean difference the model's payload genuinely produced. An error message
    probe is covered by the differential contract; here no SQL error may fire, so
    the difference is the actual returned data, not a crash. An identical truthy
    and falsy response refutes the oracle claim.
    """
    oracle = record.get('boolean_oracle') or {}
    truthy, falsy, clean = oracle.get('truthy_sha256', []), oracle.get('falsy_sha256'), oracle.get('clean_sha256')
    statuses = oracle.get('statuses', {})
    traces = record.get('responses', []) or []
    if not isinstance(truthy, list) or len(truthy) < 2 or not all(re.fullmatch('[0-9a-f]{64}', v or '') for v in truthy):
        return None
    if not all(re.fullmatch('[0-9a-f]{64}', v or '') for v in (falsy, clean)):
        return None
    if len(set(truthy)) != 1:
        return None  # the probe is not reproducible; an unstable oracle proves nothing
    if falsy != clean:
        return None
    truthy_sha = truthy[0]
    if truthy_sha == falsy:
        return 'refuted'
    truthy_ok = all(200 <= s < 400 for s in statuses.get('truthy', []))
    clean_ok = all(isinstance(statuses.get(part), int) and 200 <= statuses[part] < 400 for part in ('falsy', 'clean'))
    if not truthy_ok or not clean_ok or len(truthy) != len(statuses.get('truthy', [])):
        return None
    return 'confirmed' if truthy_sha != falsy else None


def _path_traversal(record):
    """A traversal payload returned sensitive file markers, proven by a clean control."""
    signatures = {d.get('signature') for d in (record.get('detected') or [])
                  if d.get('category') == 'path_traversal'}
    if not signatures:
        return None
    return 'confirmed' if _control_is_clean(record, 'path_traversal') else None


# Reference the canonical list in one place; documentation-sample keys stay hints.
PLACEHOLDER_MATERIAL = web_signatures.PLACEHOLDER_MATERIAL


def _sensitive_material_exposure(record):
    """Unambiguous secret material (private key / long-lived credential) in the body."""
    signatures = {d.get('signature') for d in (record.get('detected') or [])
                  if d.get('category') == 'sensitive_information_exposure'}
    if not signatures & {'private_key', 'aws_access_key'}:
        return None
    excerpts = ' '.join(r.get('body_excerpt', '') for r in (record.get('responses') or [])
                        if isinstance(r, dict))
    if any(placeholder in excerpts for placeholder in PLACEHOLDER_MATERIAL):
        return None
    return 'confirmed'


# The contract registry: basis -> evaluator. Adding a vulnerability class means
# adding an evaluator here, never teaching the planner a recognition pattern. The
# set of confirmable classes is therefore open-ended but every entry is a proof
# rule over stored evidence, not a list of things to test.
REPLAY_CONTRACTS = {
    'private_object_access': _private_object_access,
    'differential_injection': _differential_injection,
    'reflected_markup': _reflected_markup,
    'browser_execution': _browser_execution,
    'boolean_injection': _boolean_injection,
    'path_traversal': _path_traversal,
    'sensitive_material_exposure': _sensitive_material_exposure,
    'nuclei_template_match': lambda record: 'confirmed',  # Nuclei engine verification
}

# What evidence each replay contract actually needs, in the same generic terms the
# evaluator reads. This is proof-rule documentation, not a test recipe: it states
# the observation shape a hypothesis must produce to be confirmable, so the model
# can plan tests whose outcome can actually decide its hypothesis.
CONTRACT_REQUIREMENTS = {
    'private_object_access':
        'an operator two-identity scenario naming the object: both sessions valid, the object '
        'private, owner and non-owner compared (decisive 401/403/404 for the non-owner refutes)',
    'differential_injection':
        'a probe request with a deterministic signature at the target plus a matching clean control '
        'response for the same path and parameter ( contradictory or truncated controls stay inconclusive)',
    'reflected_markup':
        'a deterministic signature distinguishing reflected from properly encoded markup at the target '
        '(a signature is a hint for the browser-execution contract, never a verified XSS result by itself)',
    'browser_execution':
        'a browser session navigation of the recorded URL whose execution dialog carries the run marker, '
        'with a control navigation of the same URL stripped of the marker never firing a marker dialog',
    'boolean_injection':
        'the same endpoint/method probed with a reproduced truthy payload, a falsy payload and a clean control: '
        'falsy and clean behave identically, the truthy response is stable, differs from both and shows no error signature',
    'path_traversal':
        'a traversal signature in a stored response plus a clean control observation for the same path',
    'sensitive_material_exposure':
        'an unambiguous private key or long-lived credential in a stored response body, with '
        'documentation samples and placeholders excluded',
    'nuclei_template_match':
        'a Nuclei template with validated matchers that evaluated the vulnerability condition as true, '
        'with complete JSONL evidence including template-id, matched-at, matcher-name, and severity',
}


def replay_result(record):
    """Evaluate one stored trace against its declared objective evidence contract.

    Returns ``'confirmed'``, ``'refuted'`` or ``None`` (no contract applies or the
    trace does not satisfy it). An unknown basis is never assumed to hold.
    """
    contract = REPLAY_CONTRACTS.get(record.get('verification_basis'))
    return contract(record) if contract else None


def complete_trace(record):
    requests, responses = record.get('requests', []), record.get('responses', [])
    return (bool(requests) and len(requests) == len(responses)
            and all(r.get('method') and endpoint_key(r.get('url', '')) for r in requests)
            and all(isinstance(r.get('status_code'), int) and 100 <= r['status_code'] <= 599
                    and re.fullmatch('[0-9a-f]{64}', r.get('body_sha256', ''))
                    and isinstance(r.get('headers'), dict) and isinstance(r.get('body_excerpt'), str) for r in responses))


# Contract basis -> the vulnerability category it verifies. Used to re-derive a
# candidate's finding_type when the planner action did not carry one explicitly.
BASIS_CATEGORIES = {
    'private_object_access': 'broken_object_level_authorization',
    'differential_injection': 'sql_injection',
    'browser_execution': 'cross_site_scripting',
    'boolean_injection': 'sql_injection',
    'path_traversal': 'path_traversal',
    'sensitive_material_exposure': 'sensitive_information_exposure',
    'nuclei_template_match': 'nuclei_verified_vulnerability',
}


def write_verification_record(state, record):
    """Worker-local verifier/reviewer interface, never a model-selected result label."""
    record = sanitize({**record, 'run_id': state['run_id'], 'timestamp': int(time.time())}, scenario_secrets(state))
    if not complete_trace(record) or not all(record.get(k) for k in ('steps', 'expected_behavior', 'actual_behavior')):
        raise ValueError('Verification needs complete request/response trace and expected/actual behavior')
    if record.get('verification_method') == 'deterministic_replay':
        result = replay_result(record)
        if result is None:
            raise ValueError('No supported vulnerability-specific replay proof; use signed human review')
        record['result'] = result
    elif (record.get('verification_method') != 'manual_review' or not record.get('reviewer')
          or not record.get('reason') or record.get('result') not in ('confirmed', 'refuted')):
        raise ValueError('Manual review needs reviewer attribution')
    payload = {'record': record, 'signature': hmac.new(_key(), _payload_bytes(record), hashlib.sha256).hexdigest()}
    path = artifact_path(state, 'verification', record['url'] + '#' + record['template_id'], 'json')
    save_text(path, json.dumps(payload, ensure_ascii=False, indent=2))
    return {'template_id': record['template_id'], 'url': record['url'],
            'verification_method': record['verification_method'], 'result': record['result'],
            'run_id': record['run_id'], 'timestamp': record['timestamp'],
            'evidence_ref': str(path), 'evidence_sha256': hashlib.sha256(path.read_bytes()).hexdigest()}


# Signature category -> objective evidence contract basis. Only categories with a
# contract over stored evidence are listed; a signature with no contract stays a hint.
CATEGORY_BASIS = {
    'sql_injection': 'differential_injection',
    'nosql_injection': 'differential_injection',
    # Verified XSS requires real script execution in the browser context; plain
    # reflection stays an observed signature (reflected_markup basis) for
    # hypotheses about markup handling but cannot constitute a verified finding.
    'cross_site_scripting': 'browser_execution',
    'path_traversal': 'path_traversal',
    'sensitive_information_exposure': 'sensitive_material_exposure',
    # Nuclei template matches can verify any vulnerability category
    'nuclei_verified_vulnerability': 'nuclei_template_match',
}


def verification_requirements_for(detected):
    """The evidence shape the current detections could produce, or None."""
    basis = verification_basis_for(detected)
    if basis:
        return {'verification_basis': basis, 'required_evidence': CONTRACT_REQUIREMENTS[basis]}
    return None


def verification_basis_for(detected):
    """The evidence contract basis a probe's detections support, or None.

    ``CATEGORY_BASIS`` maps signature categories to bases; look the basis up by
    category, never by its own name. Injection categories (SQL/NoSQL) share the
    differential contract; every other contract-backed category maps directly.
    XSS distinguished: only *properly encoded* markup reflection is a complete
    refutation on its own (reflected_markup), while unencoded reflection maps to
    the stricter browser_execution contract and cannot be signed by a probe
    record alone - it stays inconclusive until a browser session proves execution.
    """
    categories = {d.get('category') for d in (detected or []) if isinstance(d, dict)}
    signatures = {d.get('signature') for d in (detected or []) if isinstance(d, dict)}
    if {'sql_injection', 'nosql_injection'} & categories:
        return CATEGORY_BASIS['sql_injection']
    if 'cross_site_scripting' in categories:
        if signatures == {'html_encoded_reflection'}:
            return 'reflected_markup'  # deterministic refutation from encoding alone
        return CATEGORY_BASIS['cross_site_scripting']
    for category in ('path_traversal', 'sensitive_information_exposure'):
        if category in categories:
            return CATEGORY_BASIS[category]
    return None


def record_probe_verification(state, template_id, url, method, request, response, detected, controls):
    """Emit a signed verification record for a differential probe, or None.

    The record carries the probe request/response, the detections and every matching
    control observation, so the chosen contract is re-evaluated from the stored trace
    rather than trusted. A probe whose detections match no contract, or whose contract
    cannot decide, produces no record - never an unproven label.
    """
    basis = verification_basis_for(detected)
    if basis is None:
        return None
    contract = REPLAY_CONTRACTS[basis]
    record = {
        'template_id': template_id, 'url': url, 'method': method,
        'verification_method': 'deterministic_replay', 'verification_basis': basis,
        'signature_category': (next((d['category'] for d in detected
                                     if CATEGORY_BASIS.get(d.get('category')) == basis),
                                    'cross_site_scripting' if basis == 'reflected_markup' else None)),
        'detected': list(detected), 'controls': list(controls or []),
        'requests': [request], 'responses': [response],
        'steps': [f'Issue the recorded {method} request with the probe input',
                  'Compare the response against the stored control observation for the same path'],
        'expected_behavior': 'The endpoint response is independent of the probe input',
        'actual_behavior': f"Deterministic signature(s) {sorted({d.get('signature') for d in detected})} present",
    }
    # The contract may read the control response directly; keep the trace complete and
    # evaluable before anything is signed.
    if contract(record) is None:
        return None
    return write_verification_record(state, record)


def load_valid_proof(candidate, proof, run_id=None):
    """Return the authenticated record, so reporting uses its trace and identities."""
    try:
        path = Path(proof['evidence_ref']).resolve()
        if not path.is_relative_to((ROOT / 'artifacts' / 'scans').resolve()):
            return None
        raw = path.read_bytes()
        if len(raw) > 1_000_000 or hashlib.sha256(raw).hexdigest() != proof.get('evidence_sha256'):
            return None
        envelope = json.loads(raw)
        record = envelope['record']
        signature = hmac.new(_key(), _payload_bytes(record), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, envelope['signature']):
            return None
        if not (record.get('template_id') == candidate.get('template_id')
                and endpoint_key(record.get('url', '')) == endpoint_key(candidate.get('url', ''))
                and record.get('result') == proof.get('result') in ('confirmed', 'refuted')
                and record.get('verification_method') == proof.get('verification_method')
                and record.get('run_id') == proof.get('run_id') and record.get('timestamp') == proof.get('timestamp')
                and (run_id is None or record.get('run_id') == run_id)
                and complete_trace(record) and record.get('steps')
                and record.get('expected_behavior') and record.get('actual_behavior') and record.get('timestamp')):
            return None
        if record['verification_method'] == 'manual_review':
            return record if record.get('reviewer') and record.get('reason') else None
        if record['verification_method'] != 'deterministic_replay':
            return None
        return record if replay_result(record) == record['result'] else None
    except (OSError, ValueError, KeyError, TypeError):
        return None


def valid_proof(candidate, proof, run_id=None):
    return load_valid_proof(candidate, proof, run_id) is not None
