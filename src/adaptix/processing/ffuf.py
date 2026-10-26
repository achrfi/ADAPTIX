"""Import operator-supplied ffuf JSON as bounded, unverified offline evidence."""
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import stat

from src.adaptix.evidence.sanitize import sanitize, scenario_secrets
from src.adaptix.processing.normalize import deduplicate
from src.adaptix.security.guard import allowed_url_for_state
from src.adaptix.security.scope import endpoint_key
from src.adaptix.workflow.events import log

MAX_FILE_BYTES = 2_000_000
MAX_RESULTS = 1000
MAX_IMPORTS = 8
CONTEXT_ROWS = 8


def is_operator_review(state):
    """Review-only unless the operator explicitly released the import to planning.

    When ``ffuf_into_assessment`` is set, the imported observations stay in the
    run as *unverified provenance* (route_existence_verified=False) and the
    adaptive graph may plan bounded, authorized actions on them. Without that
    opt-in flag every import is review-only: no tools execute, as before.
    """
    if bool(state.get('ffuf_into_assessment')):
        return False
    return bool(state.get('operator_recon_review_only') or state.get('ffuf_import_documents')
                or state.get('ffuf_imports') or state.get('ffuf_observations'))


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate JSON object key')
        result[key] = value
    return result


def _result(row):
    if not isinstance(row, dict):
        return None
    url, status = row.get('url'), row.get('status')
    if (not isinstance(url, str) or len(url) > 4096 or not endpoint_key(url)
            or any(ord(ch) < 32 for ch in url)
            or type(status) is not int or not 100 <= status <= 599):
        return None
    result = {'url': url, 'status': status}
    for name in ('length', 'words', 'lines'):
        value = row.get(name)
        if value is not None:
            if type(value) is not int or not 0 <= value <= 10 ** 12:
                return None
            result[name] = value
    # Command lines, credentials, request input, body and local output paths never enter state.
    return result


def load_ffuf_files(paths):
    """Local CLI boundary only. Graph/API callers cannot request arbitrary file reads."""
    if len(paths) > MAX_IMPORTS:
        raise ValueError(f'At most {MAX_IMPORTS} ffuf files may be imported')
    documents = []
    for source in paths:
        path = Path(source)
        if not stat.S_ISREG(path.stat().st_mode):
            raise ValueError('ffuf input must be a regular JSON file')
        with path.open('rb') as stream:
            raw = stream.read(MAX_FILE_BYTES + 1)
        if len(raw) > MAX_FILE_BYTES:
            raise ValueError('ffuf JSON exceeds the two-megabyte input limit')
        try:
            data = json.loads(raw, object_pairs_hook=_object,
                              parse_constant=lambda value: (_ for _ in ()).throw(ValueError('Non-finite JSON number')))
        except (UnicodeError, RecursionError, ValueError) as exc:
            raise ValueError('Invalid ffuf JSON') from exc
        if not isinstance(data, dict) or not isinstance(data.get('results'), list):
            raise ValueError('Expected standard ffuf JSON with a results array')
        if len(data['results']) > MAX_RESULTS:
            raise ValueError(f'ffuf JSON exceeds {MAX_RESULTS} result rows')
        configuration = data.get('config') or {}
        if not isinstance(configuration, dict):
            raise ValueError('Invalid ffuf configuration metadata')
        method = configuration.get('method', 'UNKNOWN')
        if not isinstance(method, str) or not re.fullmatch(r'[A-Z]{1,16}', method):
            raise ValueError('Invalid ffuf HTTP method metadata')
        documents.append({'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw),
                          'method': method, 'results': [_result(row) for row in data['results']]})
    return documents


def import_ffuf_documents(state):
    """Normalize only after authorization. Never resolve DNS, request URLs or launch tools."""
    documents = state.get('ffuf_import_documents', [])
    if not documents:
        if state.get('ffuf_imports') or state.get('ffuf_observations'):
            raise ValueError('Supply prepared ffuf_import_documents, not normalized output fields')
        return {}
    if not isinstance(documents, list) or len(documents) > MAX_IMPORTS:
        raise ValueError('Invalid ffuf document batch')
    assessment_seed = bool(state.get('ffuf_into_assessment'))
    observations, imports, seen = [], [], set()
    secrets = scenario_secrets(state)
    for document in documents:
        if not isinstance(document, dict):
            raise ValueError('Invalid ffuf document')
        digest, size, rows = document.get('sha256'), document.get('bytes'), document.get('results')
        method = document.get('method', 'UNKNOWN')
        if (not isinstance(digest, str) or not re.fullmatch(r'[0-9a-f]{64}', digest)
                or type(size) is not int or not 0 <= size <= MAX_FILE_BYTES
                or not isinstance(rows, list) or len(rows) > MAX_RESULTS
                or not isinstance(method, str) or not re.fullmatch(r'[A-Z]{1,16}', method)):
            raise ValueError('Invalid ffuf document metadata or bounds')
        if digest in seen:
            continue
        seen.add(digest)
        rejected = Counter()
        accepted = []
        for row in rows:
            row = _result(row)
            if row is None:
                rejected['invalid_record'] += 1
                continue
            if not allowed_url_for_state(state, row['url']):
                rejected['outside_scope'] += 1
                continue
            accepted.append(sanitize({
                'url': row['url'], 'status_code': row['status'], 'method': method,
                **{key: row[key] for key in ('length', 'words', 'lines') if key in row},
                'source': 'operator_ffuf_json', 'source_sha256': digest,
                'route_existence_verified': False, 'verification_status': 'operator_supplied_unverified',
            }, secrets))
        unique = deduplicate('ffuf_observations', accepted)
        observations.extend(unique)
        imports.append({'source_sha256': digest, 'bytes': size, 'input_rows': len(rows),
                        'accepted_rows': len(unique), 'rejected_rows': sum(rejected.values()),
                        'duplicate_rows': len(accepted) - len(unique), 'rejection_counts': dict(rejected),
                        'assessment_seed': assessment_seed,
                        'provenance': 'operator_supplied; file hash is provenance, not authenticity proof'})
    if assessment_seed:
        # Explicit operator opt-in: the observations stay unverified inventory
        # provenance for planning; baseline/scanner/tool gating stays whatever the
        # operator configured. Without this flag the run stays review-only.
        return {'ffuf_import_documents': [], 'ffuf_imports': imports,
                'ffuf_observations': observations,
                'structured_observations': {**state.get('structured_observations', {}),
                                            'ffuf_observations': observations},
                'events': log(state, f'Operator ffuf import (assessment seed): {len(imports)} file(s), '
                                     f'{len(observations)} unverified observations released to planning')}
    return {'ffuf_import_documents': [], 'ffuf_imports': imports,
            'ffuf_observations': observations, 'operator_recon_review_only': True,
            'baseline_disabled': True, 'scanner_disabled': True,
            'structured_observations': {**state.get('structured_observations', {}),
                                        'ffuf_observations': observations},
            'events': log(state, f'Operator ffuf import: {len(imports)} file(s), '
                          f'{len(observations)} observations; review only')}


def import_summary(state):
    seed = bool(state.get('ffuf_into_assessment'))
    imports = state.get('ffuf_imports', [])
    return {'mode': 'operator_supplied_assessment_seed' if seed else 'operator_supplied_offline_review',
            'assessment_seed': seed, 'files': len(imports),
            'observations': len(state.get('ffuf_observations', [])),
            'rejected_rows': sum(row['rejected_rows'] for row in imports),
            'duplicate_rows': sum(row['duplicate_rows'] for row in imports),
            'context_sample_limit': CONTEXT_ROWS,
            'note': 'Unverified operator observations; repeated 200 responses may be wildcard/fallback pages. '
                    'Full accepted rows remain in the report. The observations carry provenance only '
                    '(route_existence_verified=False) and never vulnerability evidence.'
                    + (' They are released to planning as unverified seeds; scope, budget and approval '
                       'gates still apply.' if seed else ' No tool execution or route promotion.')}
