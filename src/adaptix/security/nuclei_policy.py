"""Snapshot and classify exact templates before Nuclei can issue requests."""
import hashlib
import json
import os
import re
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
        return {'id': str(data.get('id', '')), 'sha256': digest, 'tags': sorted(set(tags)), 'methods': methods, 'reasons': sorted(set(reasons))}
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
        roots = [template_root() / 'http']
    paths = sorted({path for root in roots for path in ([root] if root.is_file() else root.rglob('*.yaml'))})
    if not paths:
        raise ValueError('Nuclei template catalog is missing or empty')
    policy = config('nuclei.yaml').get('policy', {})
    if mode == 'adaptive' and not profile['tags']:
        seeds = {str((template_root() / name).resolve()) for name in policy.get('discovery_templates',
                 ['http/technologies/tech-detect.yaml', 'http/technologies/favicon-detect.yaml'])}
        paths = [path for path in paths if str(path.resolve()) in seeds]
    observe_tags = set(policy.get('observation_tags', ['tech', 'detect', 'favicon', 'panel', 'baseline']))
    denied_tags = {'intrusive', 'dos', 'fuzz', 'fuzzing', 'dast', 'rce', 'sqli', 'ssrf', 'xss', 'lfi', 'oast', 'bruteforce', 'vuln', 'cve', 'default-login'}
    trusted = set(policy.get('trusted_observation_sha256', []))
    files = []
    for path in paths:
        raw = path.read_bytes()
        row = {**inspect_template(raw), 'path': str(path)}
        tags = set(row['tags'])
        if mode == 'adaptive' and profile['tags'] and not tags.intersection(profile['tags']):
            continue
        if mode == 'adaptive' and not profile['tags'] and not tags.intersection({'tech', 'detect', 'favicon'}):
            continue
        reasons = list(row['reasons'])
        if not tags.intersection(observe_tags) and row['sha256'] not in trusted:
            reasons.append('Not in an observation class or operator-reviewed hash allowlist')
        if tags.intersection(denied_tags) or any(re.fullmatch(r'cve\d+', tag) for tag in tags):
            reasons.append('Active/intrusive vulnerability class')
        row['risk'] = 'state_change' if reasons else 'observe'
        row['reasons'] = sorted(set(reasons))
        files.append(row)
    fingerprint = hashlib.sha256(json.dumps({'target': target, 'mode': mode, 'tags': profile['tags'],
        'files': [(row['path'], row['sha256'], row['risk']) for row in files]}, sort_keys=True).encode()).hexdigest()
    action = {'tool': 'nuclei', 'target': target}
    spec = {'risk': 'state_change', 'operation': 'nuclei_exact_manifest', 'manifest_sha256': fingerprint}
    authorization = approval_for(state, action, spec)
    active = [row for row in files if row['risk'] != 'observe']
    chosen = files if authorization['result'] == 'allowed' else [row for row in files if row['risk'] == 'observe']
    manifest = {**profile, 'manifest_sha256': fingerprint, 'templates': files,
                'selected_count': len(files), 'executable_count': len(chosen), 'approval_required_count': len(active),
                'coverage': 'full_selected_manifest' if not active or authorization['result'] == 'allowed' else 'observation_subset',
                'approval': authorization, 'exact_path': mode == 'baseline'}
    path = artifact_path(state, 'nuclei-manifest', target + fingerprint, 'json')
    save_text(path, json.dumps(manifest, indent=2))
    manifest['manifest_ref'] = str(path)
    manifest['_chosen'] = chosen
    return manifest


def materialize(state, manifest):
    selected_digest = hashlib.sha256(json.dumps([row['sha256'] for row in manifest['_chosen']]).encode()).hexdigest()
    base = artifact_path(state, 'nuclei-snapshot', manifest['manifest_sha256'] + selected_digest, 'dir')
    base.mkdir(mode=0o700, exist_ok=True)
    for row in manifest['_chosen']:
        content = Path(row['path']).read_bytes()
        if hashlib.sha256(content).hexdigest() != row['sha256']:
            raise ValueError('Template changed after manifest approval; replan required')
        destination = base / (row['sha256'] + '.yaml')
        destination.write_bytes(content)
        destination.chmod(0o600)
    expected = {row['sha256'] + '.yaml' for row in manifest['_chosen']} | {'isolated-config.yml', '.templates-index', '.checksum', '.new-additions'}
    if any(path.name not in expected for path in base.iterdir()):
        raise ValueError('Unexpected file in isolated template snapshot')
    # Exact root is essential: native -as otherwise adds the entire installed catalog.
    empty = base / 'isolated-config.yml'
    save_text(empty, '{}\n')
    flags = list(manifest.get('flags', []))
    return ['-ud', str(base), '-t', str(base), '-config', str(empty), '-ni', *flags]
