"""Snapshot and classify exact templates before Nuclei can issue requests."""
import hashlib
import json
import os
import re
import time
from functools import lru_cache
from pathlib import Path
import yaml
from src.adaptix.config import ROOT, config
from src.adaptix.evidence.storage import artifact_path, save_text
from src.adaptix.security.action_policy import approval_for


def template_root():
    explicit = config('scope.yaml')['limits'].get('nuclei_templates_root') or os.getenv('NUCLEI_TEMPLATES_DIR')
    if explicit:
        return Path(explicit).expanduser().resolve()
    metadata = Path.home() / '.config/nuclei/.templates-config.json'
    if metadata.is_file():
        return Path(json.loads(metadata.read_text())['nuclei-templates-directory']).resolve()
    return Path.home() / 'nuclei-templates'


@lru_cache(maxsize=16384)
def inspect_template(raw):
    digest = hashlib.sha256(raw).hexdigest()
    try:
        data = yaml.load(raw, Loader=getattr(yaml, 'CSafeLoader', yaml.SafeLoader))
        if not isinstance(data, dict) or not isinstance(data.get('info'), dict):
            raise ValueError('Missing template metadata')
        tags = data['info'].get('tags', [])
        tags = [t.strip().lower() for t in tags.split(',')] if isinstance(tags, str) else tags
        requests = data.get('http', [])
        methods = sorted({str(req.get('method', 'GET')).upper() for req in requests if isinstance(req, dict)})
        reasons = []
        if not requests or not all(isinstance(req, dict) for req in requests):
            reasons.append('No inspectable HTTP requests')
        forbidden = {'flow', 'code', 'javascript', 'headless', 'dns', 'tcp', 'network', 'file', 'ssl', 'websocket', 'self-contained', 'global-matchers', 'variables', 'constants'}
        if forbidden.intersection(data):
            reasons.append('Additional execution protocol, flow or variables')
        for req in requests:
            if not isinstance(req, dict):
                continue
            if req.get('method', 'GET').upper() not in ('GET', 'HEAD'):
                reasons.append('Non-observation HTTP method')
            if any(key in req for key in ('raw', 'body', 'payloads', 'attack', 'fuzzing', 'unsafe', 'race', 'threads', 'req-condition')):
                reasons.append('Raw, payload, body or advanced request execution')
            paths = req.get('path', [])
            if not isinstance(paths, list) or not paths:
                reasons.append('Missing anchored request path')
                continue
            for path in paths:
                if not isinstance(path, str) or not path.startswith(('{{BaseURL}}', '{{RootURL}}')):
                    reasons.append('Request path is not anchored to selected origin')
                elif '{{' in path.replace('{{BaseURL}}', '').replace('{{RootURL}}', ''):
                    reasons.append('Dynamic request payload')
                elif not re.fullmatch(r'\{\{(?:BaseURL|RootURL)\}\}(?:[/?#][^\r\n]*)?', path):
                    reasons.append('Request suffix can change the selected authority')
            headers = req.get('headers', {})
            if not isinstance(headers, dict) or any(str(k).lower() in ('host', 'authorization', 'cookie') for k in headers):
                reasons.append('Template overrides endpoint or identity headers')
        # A technology matcher may mention Interactsh in the response it detects.
        # Only outgoing execution fields can initiate an interaction; matcher text
        # is not an outgoing payload. Dynamic paths/protocols are gated above too.
        execution = [{k: v for k, v in req.items() if k not in ('matchers', 'matchers-condition', 'extractors')}
                     for req in requests if isinstance(req, dict)]
        if 'interactsh' in json.dumps(execution, default=str).lower():
            reasons.append('Out-of-band interaction')
        # The isolated snapshot packages only template YAML. Any reference to
        # shipped catalog assets (wordlists/helpers) would fail at engine load
        # time or silently skip the check; detect it before approval instead.
        referenced = json.dumps(data, default=str)
        if re.search(r'\b(?:wordlists|helpers)/', referenced):
            reasons.append('External file dependency that the isolated snapshot cannot package')
        request_blocks = sum(len(req.get('path', []) or []) for req in requests
                             if isinstance(req, dict) and isinstance(req.get('path', []), list))
        return {'id': str(data.get('id', '')), 'sha256': digest, 'tags': sorted(set(tags)), 'methods': methods,
                'requests': request_blocks, 'reasons': sorted(set(reasons))}
    except Exception as exc:
        return {'id': '', 'sha256': digest, 'tags': [], 'methods': [], 'reasons': ['Uninspectable template: ' + type(exc).__name__]}


def prepare_scan(state, target, settings):
    from src.adaptix.tools.nuclei_profiles import adaptive_profile
    mode = settings.get('nuclei_templates', 'default')
    profile = adaptive_profile(state, target) if mode == 'adaptive' else {'target': target, 'mode': mode, 'strategy': 'configured', 'tags': [], 'flags': []}
    if mode == 'baseline':
        roots = [ROOT / 'templates/http-response.yaml']
    elif isinstance(mode, list):
        roots = [(ROOT / value).resolve() for value in mode]
    else:
        # Evidence-aware bounded selection: observation families for the
        # deterministic phase (generic checks run even when the fingerprint did
        # not map the target to a trusted product), and the operator-authorized
        # vulnerability-probe families for the assessment profile. Template
        # selection, mechanical inspection and approval gating stay identical
        # everywhere; only the directories the run may consider differ by mode.
        http_root = template_root() / 'http'
        families = ('technologies', 'misconfiguration', 'exposures', 'exposed-panels', 'miscellaneous')
        if mode == 'assessment':
            families = ('vulnerabilities', 'misconfiguration', 'cves', 'exposures', 'exposed-panels')
        elif mode == 'default':
            families = None  # full installed catalog, cut by cap/ranking below
        if families is None:
            roots = [http_root]
        else:
            roots = [http_root / name for name in families if (http_root / name).is_dir()]
            if not roots and http_root.is_dir():
                # Catalogs without the named family layout keep full coverage
                # instead of silently excluding everything; gating and cap still
                # apply to every row.
                roots = [http_root]
    root_paths = [[path for path in ([root] if root.is_file() else root.rglob('*.yaml'))] for root in roots]
    paths = sorted({path for group in root_paths for path in group})
    if not paths:
        raise ValueError('Nuclei template catalog is missing or empty')
    policy = config('nuclei.yaml').get('policy', {})
    seeds = {str((template_root() / name).resolve()): index
             for index, name in enumerate(policy.get('discovery_templates',
             ['http/technologies/tech-detect.yaml', 'http/technologies/favicon-detect.yaml']))}
    observe_tags = set(policy.get('observation_tags', ['tech', 'detect', 'favicon', 'panel', 'baseline']))
    denied_tags = {'intrusive', 'dos', 'fuzz', 'fuzzing', 'dast', 'rce', 'sqli', 'ssrf', 'xss', 'lfi', 'oast', 'bruteforce', 'vuln', 'cve', 'default-login'}
    trusted = set(policy.get('trusted_observation_sha256', []))
    # Exact template contents an operator reviewed may respond to vulnerability
    # classes (exposed files, misconfiguration, info disclosure, scripted XSS or
    # SQLi probes that are mechanically safe). Reviewing opens exactly the listed
    # templates, never a tag; unsafe execution mechanics and the permanentable
    # classes stay detached from review below.
    reviewed = set(policy.get('reviewed_observation_sha256', []))
    hard_denied = {'intrusive', 'dos', 'oast', 'fuzz', 'fuzzing', 'bruteforce', 'default-login'}
    files = []
    for path in paths:
        raw = path.read_bytes()
        row = {**inspect_template(raw), 'path': str(path)}
        tags = set(row['tags'])
        mechanical = list(row['reasons'])
        # Mechanical safety never bends for review: only templates whose execution
        # is provably an anchored GET/HEAD observation may run reviewed.
        permanent = {tag for tag in tags if tag in hard_denied}
        allowlisted = row['sha256'] in reviewed and not mechanical and not permanent
        # Evidence-aware family filter: in adaptive mode a trusted observed product
        # tag directly restricts the catalog rows considered. It never widens a
        # denied class; rows failing the filter are still fully counted.
        if mode == 'adaptive' and profile.get('tags') and not tags.intersection(profile['tags']):
            continue
        row['seed'] = seeds.get(str(path.resolve()), None)
        row['family'] = path.parent.name
        reasons = list(mechanical)
        if not tags.intersection(observe_tags) and row['sha256'] not in trusted and not allowlisted:
            reasons.append('Not in an observation class or operator-reviewed hash allowlist')
        if tags.intersection(denied_tags) or any(re.fullmatch(r'cve\d+', tag) for tag in tags):
            if not allowlisted:
                reasons.append('Active/intrusive vulnerability class')
        if permanent and not allowlisted:
            reasons.append('Permanently denied class (intrusive/dos/out-of-band/fuzz)')
        row['risk'] = 'state_change' if reasons else 'observe'
        row['allowlisted'] = allowlisted
        row['reasons'] = sorted(set(reasons))
        files.append(row)
    all_evaluated = len(files)
    # Deterministic coverage-first ranking: configured discovery seeds always come
    # first (fingerprinting stays possible even at cap=1), then a fair round-robin
    # over the remaining families in policy order, each internally ordered by
    # request cost and id - deliberate category spread, never catalog-alphabetical.
    def _row_order(row):
        return (int(row.get('requests', 0)), row['path'])
    groups = [[] for _ in roots]
    for index, root in enumerate(roots):
        if root.is_file():
            groups[index] = [row for row in files if row['path'] == str(root)]
        elif root.is_dir():
            in_family = ([row for row in files if row.get('seed') is None] if len(roots) == 1
                         else [row for row in files if row['family'] == str(root.name) and row.get('seed') is None])
            groups[index] = in_family
    seed_rows = sorted([row for row in files if row.get('seed') is not None], key=lambda row: row['seed'])
    rows = list(seed_rows)
    take = [sorted(group, key=_row_order) for group in groups if group]
    while any(take):
        for group in list(take):
            if group:
                rows.append(group.pop(0))
            else:
                take.remove(group)
        if all(not g for g in take):
            break
    # A wall-clock-bounded automatic phase cannot select thousands of templates
    # and call the ceiling honest. The cap is applied after evidence filtering and
    # ranking (never instead of them), the configured discovery seeds are exempt,
    # and the discarded remainder is named as a limitation rather than dropped.
    cap = settings.get('nuclei_template_cap')
    selection_note = None
    if isinstance(cap, int) and not isinstance(cap, bool) and cap > 0 and len(rows) > cap:
        seed_rows = [row for row in rows if row.get('seed') is not None]
        remainder = [row for row in rows if row.get('seed') is None]
        rows = seed_rows + remainder[:max(0, cap - len(seed_rows))]
        selection_note = (f'{all_evaluated - len(rows)} template(s) beyond the ranked {cap}-template cap '
                          'were not selected; recorded, not silently skipped')
    files = rows
    fingerprint = hashlib.sha256(json.dumps({'target': target, 'mode': mode, 'tags': profile['tags'],
        'files': [(row['path'], row['sha256'], row['risk']) for row in files]}, sort_keys=True).encode()).hexdigest()
    # Category coverage telemetry over the retained manifest: what supported
    # checks the selected templates would exercise, for tested/skipped categories
    # reporting (vulnerability-class templates are gated; counts are still the
    # selected manifest's coverage, not execution).
    class_tags = ('sqli', 'xss', 'lfi', 'ssrf', 'rce', 'vuln', 'cve', 'exposure', 'exposures',
                  'misconfig', 'panel', 'tech', 'detect', 'traversal', 'token-spray')
    manifest_categories = {}
    for row in files:
        for tag in row['tags']:
            if tag in class_tags:
                manifest_categories[tag] = manifest_categories.get(tag, 0) + 1
    action = {'tool': 'nuclei', 'target': target}
    active = [row for row in files if row['risk'] != 'observe']
    if active:
        # Only a manifest that actually gates an active template can need human
        # approval; the request to approve is bound to the exact manifest digest.
        spec = {'risk': 'state_change', 'operation': 'nuclei_exact_manifest', 'manifest_sha256': fingerprint}
        authorization = approval_for(state, action, spec)
    else:
        # Nothing in this manifest is gated, so no human approval applies and none is
        # required. Reporting "required/denied" here would contradict
        # approval_required_count=0 and mislabel a pure observation as an unauthorized
        # state change; the executor independently reaches the same observe verdict.
        authorization = {'required': False, 'result': 'allowed', 'operation': 'nuclei_observation_subset',
                         'reason': 'Manifest selected only observation-class templates'}
    chosen = files if authorization['result'] == 'allowed' else [row for row in files if row['risk'] == 'observe']
    manifest = {**profile, 'manifest_sha256': fingerprint, 'templates': files,
                'selected_count': len(files), 'executable_count': len(chosen), 'approval_required_count': len(active),
                'coverage': 'full_selected_manifest' if not active or authorization['result'] == 'allowed' else 'observation_subset',
                'approval': authorization, 'exact_path': mode == 'baseline',
                'evaluated_templates': all_evaluated,
                'families': [str(root.name) for root in roots if root.is_dir()],
                # Exact request counts are not observable in Nuclei JSONL output;
                # the ceiling comes from the reviewed manifests and is enforced by
                # policy rate/concurrency limits shared with the whole run.
                'request_ceiling_per_target': sum(int(row.get('requests', 0)) for row in chosen),
                'category_counts': manifest_categories,
                # Listed on the manifest so the adapter classifies matches against
                # the same policy labels the manifest was authorized under, without
                # re-reading configuration after execution.
                'observation_tags': sorted(observe_tags)}
    if selection_note:
        manifest['selection_note'] = selection_note
    path = artifact_path(state, 'nuclei-manifest', target + fingerprint, 'json')
    save_text(path, json.dumps(manifest, indent=2))
    manifest['manifest_ref'] = str(path)
    manifest['_chosen'] = chosen
    return manifest


def materialize(state, manifest):
    selected_digest = hashlib.sha256(json.dumps([row['sha256'] for row in manifest['_chosen']]).encode()).hexdigest()
    base = artifact_path(state, 'nuclei-snapshot', manifest['manifest_sha256'] + selected_digest, 'dir')
    expected = {row['sha256'] + '.yaml' for row in manifest['_chosen']} | {'isolated-config.yml', '.templates-index', '.checksum', '.new-additions'}
    # The cache directory name is derived from approved hashes only, so it can
    # never legitimately hold anything else - let alone a synced repo clone,
    # which is exactly what Nuclei -ud turned an earlier snapshot into.
    # Preserve the content (audit trail) by moving it aside, then re-materialize.
    if base.is_dir():
        unexpected = [path.name for path in base.iterdir() if path.name not in expected]
        if unexpected:
            tainted = base.with_name(base.name + f'-tainted-{int(time.time())}')
            base.rename(tainted)
    base.mkdir(mode=0o700, exist_ok=True)
    for row in manifest['_chosen']:
        content = Path(row['path']).read_bytes()
        if hashlib.sha256(content).hexdigest() != row['sha256']:
            raise ValueError('Template changed after manifest approval; replan required')
        destination = base / (row['sha256'] + '.yaml')
        destination.write_bytes(content)
        destination.chmod(0o600)
    if any(path.name not in expected for path in base.iterdir()):
        raise ValueError('Unexpected file in isolated template snapshot')
    # Exact root is essential: native -as otherwise adds the entire installed catalog.
    empty = base / 'isolated-config.yml'
    save_text(empty, '{}\n')
    # -ud is deliberately absent: it makes Nuclei treat the directory as its
    # template cache and can sync/delete it; -t alone bounds the engine to the
    # approved snapshot, and the launcher re-verifies every file hash afterwards.
    flags = list(manifest.get('flags', []))
    return ['-t', str(base), '-config', str(empty), '-ni', *flags]
