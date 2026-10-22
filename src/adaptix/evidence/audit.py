"""Sanitized checkpoints and a self-contained audit bundle; replay never invokes tools."""
import hashlib
import json
import subprocess
import platform
from pathlib import Path
from src.adaptix.config import ROOT
from src.adaptix.evidence.storage import artifact_path, save_text
from src.adaptix.evidence.sanitize import sanitize, scenario_secrets


def write_json(state, stage, value):
    path = artifact_path(state, stage, stage, 'json')
    save_text(path, json.dumps(sanitize(value, scenario_secrets(state)), ensure_ascii=False, indent=2, default=str))
    return path


def checkpoint(state):
    if not state.get('run_id'):
        return None
    stage = f'checkpoint-{state.get("iterations", 0):04d}'
    path = Path(artifact_path(state, stage, stage, 'json'))
    try:
        if path.is_file():
            existing = json.loads(path.read_text()).get('run_started_at') or 'unknown'
        else:
            existing = None
    except (OSError, ValueError):
        existing = 'unreadable'
    if existing is not None and existing != state.get('run_started_at'):
        # The directory holds another run's evidence. Rewriting it would destroy an
        # audit trail; a diagnostic replay must carry a fresh run ID.
        return None
    safe = {k: v for k, v in state.items() if k not in ('planner_cache', 'idor_scenarios', 'identity_context', 'grant', 'action_approvals')}
    return str(write_json(state, stage, safe))


def export_bundle(state, report, events):
    if not state.get('run_id'):
        return {}
    paths = {}
    try:
        git_head = subprocess.run(['git', 'rev-parse', 'HEAD'], cwd=ROOT, capture_output=True, text=True, timeout=5).stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        git_head = 'unavailable'
    source_files = [p for folder in ('src', 'lab', 'scripts', 'config') for p in (ROOT / folder).rglob('*')
                    if p.is_file() and p.suffix in ('.py', '.yaml') and '__pycache__' not in p.parts]
    source_digest = hashlib.sha256()
    for file in sorted(source_files):
        source_digest.update(file.relative_to(ROOT).as_posix().encode() + b'\0' + file.read_bytes())
    records = {
        'report': report, 'events': events, 'observations': state.get('structured_observations', {}),
        'recon': state.get('recon_inventory', []), 'decisions': state.get('planning_history', []),
        'reflection': state.get('reflection_history', []), 'token-ledger': state.get('token_ledger', []),
        'approval-audit': state.get('approval_audit', []),
        'evidence': {'verified': state.get('verified_findings', []), 'rejected': state.get('rejected_findings', []),
                     'inconclusive': state.get('inconclusive_findings', []), 'idor': state.get('idor_findings', [])},
        'run-config': {'target': state.get('target'), 'scope': state.get('scope_manifest'),
                       'authorization': state.get('authorization'), 'lab': state.get('lab_manifest', {}),
                       'model': state.get('llm_model'), 'temperature': state.get('llm_temperature', 0.2),
                       'tools': state.get('tool_catalog', {}),
                       'git_base_commit': git_head, 'source_tree_sha256': source_digest.hexdigest(),
                       'python': platform.python_version(), 'platform': platform.platform(),
                       'requirements_lock_sha256': hashlib.sha256((ROOT / 'requirements.lock').read_bytes()).hexdigest() if (ROOT / 'requirements.lock').is_file() else None,
                       'budgets': {k: ('unlimited' if state.get(k, default) is None else state.get(k, default))
                                   for k, default in {
                           'max_iterations': 20, 'token_budget': 50000, 'tool_call_budget': 20,
                           'time_budget_seconds': 1800, 'planner_retry_limit': 0,
                           'model_context_tokens': 4096, 'policy_replan_limit': 2}.items()}},
    }
    for stage, record in records.items():
        paths[stage] = str(write_json(state, stage, record))
    directory = Path(paths['report']).parent
    index = [{'path': str(p.relative_to(ROOT)), 'sha256': hashlib.sha256(p.read_bytes()).hexdigest(),
              'bytes': p.stat().st_size} for p in sorted(directory.iterdir())
             if p.is_file() and not p.name.startswith('evidence-index-')]
    paths['evidence-index'] = str(write_json(state, 'evidence-index', index))
    return paths


def inspect_bundle(index_path):
    """Integrity replay only: no network, LLM call, or executable deserialization."""
    index = json.loads(Path(index_path).read_text(encoding='utf-8'))
    checked = []
    for item in index:
        path = (ROOT / item['path']).resolve()
        if not path.is_relative_to((ROOT / 'artifacts').resolve()):
            raise ValueError('Evidence path outside artifact directory')
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != item['sha256']:
            raise ValueError(f'Evidence missing/changed: {item["path"]}')
        checked.append(item['path'])
    return {'status': 'integrity_verified', 'files_checked': len(checked), 'paths': checked}


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Replay evidence integrity without executing tools')
    parser.add_argument('--index', required=True)
    print(json.dumps(inspect_bundle(parser.parse_args().index), indent=2))
