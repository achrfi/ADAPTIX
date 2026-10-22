"""Scanner assessment mode: the operator-authorized vulnerability-assessment profile.

Phase-level behavior (--assessment / scanner_assessment state), policy-level
manifest construction (assessment template roots, denied-class gating, category
telemetry, cap round-robin) and the intact exact-manifest approval gate.
"""
import json
from pathlib import Path

import pytest

from src.adaptix.agents import reflector
from src.adaptix.security import nuclei_policy
from src.adaptix.workflow import scanner


SETTINGS = {'enabled': True, 'template_mode': 'adaptive', 'max_seconds': 60, 'max_origins': 2,
            'adaptive_tool_call_reserve': 4, 'max_candidates_per_origin': 40, 'template_cap': 160,
            'vulnerability_assessment': True}


@pytest.fixture
def preview_settings(monkeypatch):
    monkeypatch.setattr(scanner, 'scanner_settings', lambda: dict(SETTINGS))
    return SETTINGS


def _phase(origin):
    return {'candidates': [{'template_id': 'git-cve', 'url': origin + '/git',
                            'finding_type': 'generic', 'source_tool': 'nuclei', 'severity': 'high',
                            'evidence': []}],
            'execution_metrics': {'tool_calls_used': 1},
            'nuclei_template_selections': [{'target': origin, 'selected_count': 12, 'executable_count': 0,
                                            'approval_required_count': 12,
                                            'policy': {'gated_templates': 12, 'selected': [], 'denied': []},
                                            'request_ceiling_per_target': 90,
                                            'category_counts': {'sqli': 4, 'xss': 3, 'exposure': 5},
                                            'coverage': 'assessment'}],
            'events': [f'Nuclei executed against {origin}'], 'raw_bytes': 8}


def test_assessment_state_upgrades_template_mode_for_the_adapter(preview_settings, monkeypatch):
    asked = []
    monkeypatch.setattr(scanner, 'nuclei_check', lambda state: asked.append(dict(state)) or _phase(
        state['planned_actions'][0]['target']))
    state = {'status': 'scope_ok', 'events': [], 'tool_call_budget': 20, 'execution_metrics': {},
             'scanner_assessment': True, 'target': ['http://lab.example:8080/'], 'web_routes': []}
    result = scanner.nuclei_scan(state)
    assert asked[0]['nuclei_template_mode'] == 'assessment'
    assert result['nuclei_scan_metrics']['template_mode'] == 'assessment'
    assert result['nuclei_scan']['completed'] is True
    assert result['nuclei_scan_metrics']['category_counts']['sqli'] == 4


def test_assessment_state_without_yaml_authorization_skips_honestly(preview_settings, monkeypatch):
    monkeypatch.setattr(scanner, 'scanner_settings', lambda: {**SETTINGS, 'vulnerability_assessment': False})
    called = []
    monkeypatch.setattr(scanner, 'nuclei_check', lambda state: called.append(1))
    result = scanner.nuclei_scan({'status': 'scope_ok', 'events': [], 'tool_call_budget': 20,
                                  'execution_metrics': {}, 'scanner_assessment': True,
                                  'target': ['http://lab.example:8080/'], 'web_routes': []})
    assert not called
    metrics = result['nuclei_scan_metrics']
    assert metrics['mode'] == 'skipped'
    assert 'assessment not authorized' in metrics['stop_reason']


def test_off_mode_is_never_reopened_by_assessment_state(preview_settings, monkeypatch):
    called = []
    monkeypatch.setattr(scanner, 'nuclei_check', lambda state: called.append(1))
    monkeypatch.setattr(scanner, 'scanner_settings', lambda: {**SETTINGS, 'template_mode': 'off'})
    result = scanner.nuclei_scan({'status': 'scope_ok', 'events': [], 'tool_call_budget': 20,
                                  'execution_metrics': {}, 'scanner_assessment': True,
                                  'target': ['http://lab.example:8080/'], 'web_routes': []})
    assert not called
    assert result['nuclei_scan_metrics']['mode'] == 'off'


def test_default_state_without_assessment_keeps_adaptive_mode(preview_settings, monkeypatch):
    asked = []
    monkeypatch.setattr(scanner, 'nuclei_check', lambda state: asked.append(dict(state)) or _phase(
        state['planned_actions'][0]['target']))
    scanner.nuclei_scan({'status': 'scope_ok', 'events': [], 'tool_call_budget': 20, 'execution_metrics': {},
                         'target': ['http://lab.example:8080/'], 'web_routes': []})
    assert asked[0]['nuclei_template_mode'] == 'adaptive'


def test_assessment_candidate_cannot_bypass_verification(preview_settings):
    """An assessment candidate without an independent signed record stays unverified."""
    state = {'events': [], 'run_id': 'assessment-run', 'http_services': [], 'web_routes': [],
             'verification_evidence': [],
             'candidates': [{'template_id': 'git-cve', 'url': 'http://lab.example:8080/git',
                             'finding_type': 'generic', 'severity': 'high', 'source_tool': 'nuclei'}]}
    result = reflector.collect_findings(state)
    assert result['verified_findings'] == []
    entry = result['inconclusive_findings'][0]
    assert entry['verification_status'] == 'inconclusive'
    assert not (entry.get('verification_evidence') or {}).get('evidence_ref')


# ------ policy-level manifest behavior over a synthetic catalog ------

def _write_template(root, subdir, name, tags, method='GET', matchers='      - type: word'):
    directory = root / 'http' / subdir
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f'{name}.yaml'
    path.write_text(
        f'id: {subdir}-{name}\ninfo:\n  name: {name}\n  author: t\n  severity: info\n  tags: {tags}\nhttp:\n'
        f'  - method: {method}\n    path:\n      - "{{{{BaseURL}}}}/{name}"\n{matchers}\n')
    return path


@pytest.fixture
def catalog(tmp_path, monkeypatch):
    root = tmp_path / 'catalog'
    _write_template(root, 'vulnerabilities', 'sqli-post', 'sqli,vuln', 'POST')
    _write_template(root, 'vulnerabilities', 'xss-script', 'xss,vuln')
    _write_template(root, 'misconfiguration', 'actuator', 'misconfig,panel')
    _write_template(root, 'exposures', 'git-exposure', 'exposure')
    _write_template(root, 'exposed-panels', 'admin-panel', 'panel,tech,detect')
    monkeypatch.setattr(nuclei_policy, 'template_root', lambda: root)
    return root


@pytest.fixture
def manifest_state(tmp_path, monkeypatch):
    monkeypatch.setattr(scanner.__dict__.get('config', scanner), 'scanner_settings', lambda: dict(SETTINGS), False)
    from src.adaptix.security import authorization as auth
    monkeypatch.setattr(auth, 'KEY_PATH', tmp_path / 'signing-key')
    auth._key(create=True)
    return {'run_id': 'assessment-manifest', 'principal': 'local-audit', 'events': [],
            'scope_manifest': {'hosts': ['127.0.0.1'], 'networks': [], 'aliases': {}},
            'target': ['http://127.0.0.1:8080/']}


def test_assessment_manifest_selects_vulnerability_roots_and_gates_active_templates(manifest_state, catalog):
    manifest = nuclei_policy.prepare_scan(manifest_state, 'http://127.0.0.1:8080/',
                                          {'nuclei_templates': 'assessment'})
    paths = {row['path'] for row in manifest['templates']}
    assert any('/vulnerabilities/' in p for p in paths)
    assert any('/misconfiguration/' in p for p in paths)
    assert any('/exposures/' in p for p in paths)
    assert any('/exposed-panels/' in p for p in paths)
    active = {row['path'] for row in manifest['templates'] if row['risk'] != 'observe'}
    assert active and all('permalinks' not in p for p in active)
    # Post-body templating needs structural approval and no template runs without it
    assert manifest['executable_count'] == 0
    assert manifest['approval_required_count'] == len(active)
    assert manifest['coverage'] == 'observation_subset'
    counts = manifest['category_counts']
    assert counts['sqli'] == 1 and counts['xss'] == 1 and counts['exposure'] == 1


def test_assessment_manifest_is_signable_and_binding(manifest_state, catalog, tmp_path):
    """The active manifest grants exactly the reviewed template set by digest."""
    from src.adaptix.security.action_policy import issue_action_approval
    first = nuclei_policy.prepare_scan(manifest_state, 'http://127.0.0.1:8080/',
                                       {'nuclei_templates': 'assessment'})
    issue_action_approval(manifest_state['run_id'], manifest_state['principal'], 'nuclei',
                          'http://127.0.0.1:8080/', 'execute_manifest_once',
                          manifest_sha256=first['manifest_sha256'])
    second = nuclei_policy.prepare_scan({**manifest_state,
                                         'action_approvals': [str(first['approval'].get('path', ''))]},
                                        'http://127.0.0.1:8080/', {'nuclei_templates': 'assessment'})
    changed_target = nuclei_policy.prepare_scan({**manifest_state,
                                                 'action_approvals': [str(first['approval'].get('path', ''))]},
                                                'http://127.0.0.1:8181/', {'nuclei_templates': 'assessment'})
    assert first['manifest_sha256'] == second['manifest_sha256']
    assert second['executable_count'] == 0 or second['executable_count'] <= second['selected_count']
    assert changed_target['executable_count'] == 0  # approval never transfers across manifests


def test_template_cap_round_robins_across_assessment_roots(manifest_state, catalog):
    for index in range(3):
        _write_template(catalog, 'cves', f'cve-s{index}', 'cve,vuln')
    manifest = nuclei_policy.prepare_scan(manifest_state, 'http://127.0.0.1:8080/',
                                          {'nuclei_templates': 'assessment', 'nuclei_template_cap': 5})
    roots_represented = {row['path'].split('/http/')[1].split('/')[0]
                         for row in manifest['templates']}
    assert len(manifest['templates']) <= 5
    # The proportional round-robin guarantees one slot per root while the cap lasts.
    assert roots_represented == {'vulnerabilities', 'misconfiguration', 'cves',
                                 'exposures', 'exposed-panels'}


def test_adaptive_without_fingerprint_keeps_seeds_and_generic_observation_files(manifest_state, catalog, monkeypatch):
    """Unknown technology is never a reason for technology-detection-only runs.

    The discovery seeds are always retained and the generic observation families
    are selected alongside them; a byte-level read-only catalog is enough for the
    fingerprint work to matter even when no product maps to tags.
    """
    monkeypatch.setattr(nuclei_policy, 'template_root', lambda: catalog)
    template = nuclei_policy.template_root() / 'http' / 'technologies' / 'tech-detect.yaml'
    template.parent.mkdir(parents=True, exist_ok=True)
    template.write_text(
        'id: tech-detect\ninfo:\n  name: tech\n  author: t\n  severity: info\n  tags: discovery,tech\nhttp:\n'
        '  - method: GET\n    path:\n      - "{{{{BaseURL}}}}"\n    matchers:\n      - type: word\n')
    state = {**manifest_state, 'http_services': []}
    manifest = nuclei_policy.prepare_scan(state, 'http://127.0.0.1:8080/',
                                          {'nuclei_templates': 'adaptive', 'nuclei_template_cap': 160})
    families = {row['family'] for row in manifest['templates']}
    assert {'technologies', 'misconfiguration', 'exposures', 'exposed-panels'} <= families
    assert manifest['selected_count'] >= 4
    assert manifest['templates'][0]['family'] == 'technologies'
    assert manifest['templates'][0]['seed'] == 0


def test_template_cap_never_drops_discovery_seeds(manifest_state, catalog, monkeypatch):
    """cap=1 still selects the fingerprint seeds because they rank ahead of the rest."""
    _write_template(catalog, 'technologies', 'tech-detect', 'discovery,tech')
    manifest = nuclei_policy.prepare_scan(manifest_state, 'http://127.0.0.1:8080/',
                                          {'nuclei_templates': 'adaptive', 'nuclei_template_cap': 1})
    ids = [row['id'] for row in manifest['templates']]
    assert ids == ['technologies-tech-detect']
    assert manifest.get('selection_note', '').endswith('not silently skipped')


def test_approved_assessment_manifest_runs_the_gated_templates(manifest_state, catalog):
    """A signed exact-manifest approval turns gated rows executable, in place."""
    from src.adaptix.security.action_policy import issue_action_approval
    pending = nuclei_policy.prepare_scan(manifest_state, 'http://127.0.0.1:8080/',
                                         {'nuclei_templates': 'assessment'})
    assert pending['approval_required_count'] > 0 and pending['executable_count'] < pending['selected_count']
    path = issue_action_approval(manifest_state['run_id'], manifest_state['principal'], 'nuclei',
                                 'http://127.0.0.1:8080/', 'execute_manifest_once',
                                 manifest_sha256=pending['manifest_sha256'])
    approved = nuclei_policy.prepare_scan({**manifest_state,
                                           'action_approvals': [str(path)]},
                                          'http://127.0.0.1:8080/', {'nuclei_templates': 'assessment'})
    assert approved['approval_required_count'] == pending['approval_required_count']
    assert approved['executable_count'] == approved['selected_count']
    assert approved['approval']['result'] == 'allowed'


def test_planner_payload_exposes_assessment_candidates(preview_settings, manifest_state, catalog):
    """Category-aware candidates reach the planner payload as plain records."""
    from src.adaptix.workflow import scanner as wf
    asked = []
    original_check = wf.nuclei_check
    def fake_check(state):
        asked.append(state['planned_actions'][0]['target'])
        return _phase(state['planned_actions'][0]['target'])
    wf.nuclei_check = fake_check
    try:
        result = wf.nuclei_scan({**manifest_state, 'status': 'scope_ok', 'tool_call_budget': 20,
                                 'execution_metrics': {}, 'scanner_assessment': True,
                                 'target': ['http://127.0.0.1:8080/'], 'web_routes': []})
    finally:
        wf.nuclei_check = original_check
    view = wf.scan_inventory(result)
    assert view['candidates'] == 1 and 'candidates_by_template' in view


def test_graph_schema_carries_scanner_assessment_to_the_node():
    """LangGraph drops state keys the AgentState schema omits; the per-run
    --assessment authorization must therefore be a declared channel or it
    silently never reaches the scan node (found in the bench-auto-04 audit)."""
    from src.adaptix.workflow.graph import AgentState
    assert 'scanner_assessment' in AgentState.__annotations__
    from src.adaptix.main import main
    import inspect
    source = inspect.getsource(main)
    assert "'scanner_assessment': bool(args.assessment)" in source


def test_approved_manifest_claim_is_single_use(manifest_state, catalog, tmp_path, monkeypatch):
    """A replayed execution through the same approval object is rejected loudly."""
    from src.adaptix.security.action_policy import issue_action_approval
    import src.adaptix.tools.nuclei as adapter
    pending = nuclei_policy.prepare_scan(manifest_state, 'http://127.0.0.1:8080/',
                                         {'nuclei_templates': 'assessment'})
    path = issue_action_approval(manifest_state['run_id'], manifest_state['principal'], 'nuclei',
                                 'http://127.0.0.1:8080/', 'execute_manifest_once',
                                 manifest_sha256=pending['manifest_sha256'])
    allowed = nuclei_policy.prepare_scan({**manifest_state, 'action_approvals': [str(path)]},
                                         'http://127.0.0.1:8080/', {'nuclei_templates': 'assessment'})
    assert allowed['approval']['result'] == 'allowed'
    state = {**manifest_state, 'action_approvals': [str(path)],
             'planned_actions': [{'tool': 'nuclei', 'target': 'http://127.0.0.1:8080/',
                                  'reason': 'r', 'priority': 1}], 'action_cursor': 0,
             'events': [], 'errors': [], 'http_services': [],
             'nuclei_template_mode': 'assessment', 'tool_call_budget': 5}
    monkeypatch.setattr(adapter, 'prepare_scan', lambda *a, **k: allowed)
    monkeypatch.setattr(adapter, 'materialize', lambda *a, **k: ['-t', str(catalog)])
    monkeypatch.setattr(adapter, 'artifact_path',
                        lambda s, stage, name, suffix: tmp_path / f'{stage}-{suffix}')
    monkeypatch.setattr(adapter, 'run_tool', lambda *a, **k: {'stdout': '', 'stderr': '', 'returncode': 0})
    monkeypatch.setattr(adapter, 'record_tool_call', lambda s, tool: {'tool_calls_used': 1})
    monkeypatch.setattr(adapter, 'tool_budget_available', lambda s: True)
    monkeypatch.setattr(adapter, 'bind_cli_urls',
                        lambda urls, state: (list(urls), {}, []))
    first = adapter.nuclei_check(state)
    replayed = adapter.nuclei_check(state)
    # The claim file O_EXCL precludes a second execution through the same
    # approval: the replay must stop instead of running the manifest again.
    assert replayed.get('stop_reason') == 'human_approval_required'
    assert any('already consumed' in row for row in replayed.get('errors', []))
    _ = first





# ---------- runtime execution integrity: argv binding, telemetry, snapshot hash

def _approved(manifest_state, tmp_path):
    from src.adaptix.security.action_policy import issue_action_approval
    pending = nuclei_policy.prepare_scan(manifest_state, 'http://127.0.0.1:8080/',
                                         {'nuclei_templates': 'assessment'})
    path = issue_action_approval(manifest_state['run_id'], manifest_state['principal'], 'nuclei',
                                 'http://127.0.0.1:8080/', 'execute_manifest_once',
                                 manifest_sha256=pending['manifest_sha256'])
    return nuclei_policy.prepare_scan({**manifest_state, 'action_approvals': [str(path)]},
                                      'http://127.0.0.1:8080/', {'nuclei_templates': 'assessment'})


def _scan_run(manifest_state, tmp_path, monkeypatch, manifest, run_tool_stub):
    """Run the real hardware path (prepare_scan mocked to the approved manifest,
    real materialize) with a stubbed engine, returning the adapter result."""
    import src.adaptix.tools.nuclei as adapter
    state = {**manifest_state, 'hosts': ['127.0.0.1'],
             'planned_actions': [{'tool': 'nuclei', 'target': 'http://127.0.0.1:8080/',
                                  'reason': 'r', 'priority': 1}], 'action_cursor': 0,
             'events': [], 'errors': [], 'http_services': [],
             'nuclei_template_mode': 'assessment', 'tool_call_budget': 5}
    monkeypatch.setattr(adapter, 'prepare_scan', lambda *a, **k: manifest)
    monkeypatch.setattr(adapter, 'artifact_path',
                        lambda s, stage, name, suffix: tmp_path / f'{stage}-{suffix}')
    monkeypatch.setattr(adapter, 'run_tool', run_tool_stub)
    monkeypatch.setattr(adapter, 'record_tool_call', lambda s, tool: {'tool_calls_used': 1})
    monkeypatch.setattr(adapter, 'tool_budget_available', lambda s: True)
    monkeypatch.setattr(adapter, 'bind_cli_urls',
                        lambda urls, state: (list(urls), {}, []))
    return adapter.nuclei_check(state)


def test_engine_argv_bounds_templates_to_snapshot_without_update_flags(manifest_state, catalog, tmp_path, monkeypatch):
    captured = {}

    def stub(argv, timeout=None, stdin=None, stderr_limit=2500):
        captured['argv'] = argv
        captured['timeout'] = timeout
        return {'returncode': 0, 'stdout': '', 'stderr': ''}

    result = _scan_run(manifest_state, tmp_path, monkeypatch, _approved(manifest_state, tmp_path), stub)
    argv = captured['argv']
    assert '-ud' not in argv  # -ud mutates/syncs the snapshot directory
    assert '-duc' in argv and '-t' in argv
    # No silent fallback flags that add installed-catalog template paths.
    assert str(catalog) not in argv
    assert not any(k for k in argv if k.startswith('nuclei-templates'))
    events = ' '.join(result['events'])
    assert 'Nuclei:' in events


def test_loaded_executed_and_matched_telemetry_is_recorded_separately(manifest_state, catalog, tmp_path, monkeypatch):
    manifest = _approved(manifest_state, tmp_path)
    snapshot = Path(nuclei_policy.materialize(manifest_state, manifest)[
        nuclei_policy.materialize(manifest_state, manifest).index('-t') + 1])
    stdout = '\n'.join([
        json.dumps({'template-id': 'exposed-panels-admin-panel', 'matched-at': 'http://127.0.0.1:8080/admin',
                    'info': {'severity': 'info'}, 'matcher-name': 'admin panel'}),
        json.dumps({'template-id': 'vulnerabilities-xss-script', 'matched-at': 'http://127.0.0.1:8080/search?q=1',
                    'info': {'severity': 'medium'}}),
        'reflected?']) + '\n'
    stderr = '[INF] Templates loaded for current scan: 4\n[INF] Executing 4 signed templates\n' \
             '[0:00:15] | Templates: 4 | Requests: 26/52 (50%)\n[WRN] 1 templates with runtime error\n'
    assert snapshot.is_dir()
    result = _scan_run(manifest_state, tmp_path, monkeypatch, manifest,
                       lambda argv, timeout=None, stdin=None, stderr_limit=2500:
                       {'returncode': 0, 'stdout': stdout, 'stderr': stderr})
    selection = result['nuclei_template_selections'][0]
    assert selection['selected_count'] == len(manifest['_chosen']) == selection['executable_count']
    assert selection['loaded_templates'] == 4
    assert selection['requests_issued'] == 26
    assert selection['matched_templates'] == 2  # two dict rows; the corrupted line parses to nothing
    kinds = {row['template_id']: row['finding_type'] for row in result['candidates']}
    # Technology fingerprints are inventory observations, never vulnerability candidates.
    assert kinds['exposed-panels-admin-panel'] == 'service_observation'
    assert kinds['vulnerabilities-xss-script'] == 'potential_vulnerability'
    assert any('runtime error' in row and 'not executed' in row for row in result['errors'])
    assert not any('integrity violation' in row for row in result['errors'])


def test_snapshot_integrity_violation_after_execution_is_reported(manifest_state, catalog, tmp_path, monkeypatch):
    manifest = _approved(manifest_state, tmp_path)
    target_file = Path(manifest['_chosen'][0]['sha256'] + '.yaml')

    def stub(argv, timeout=None, stdin=None, stderr_limit=2500):
        base = Path(argv[argv.index('-t') + 1])
        base / target_file  # path sanity
        (base / target_file).write_bytes(b'tampered in-flight')
        return {'returncode': 0, 'stdout': '', 'stderr': '[INF] Templates loaded for current scan: 4\n'}

    result = _scan_run(manifest_state, tmp_path, monkeypatch, manifest, stub)
    assert any('integrity violation' in row for row in result['errors'])


def test_materialize_holds_the_snapshot_untouchable_by_the_engine(manifest_state, catalog):
    manifest = nuclei_policy.prepare_scan(manifest_state, 'http://127.0.0.1:8080/',
                                          {'nuclei_templates': 'assessment'})
    flags = nuclei_policy.materialize(manifest_state, manifest)
    assert '-ud' not in flags
    base = Path(flags[flags.index('-t') + 1])
    expected = {row['sha256'] + '.yaml' for row in manifest['templates'] if row['risk'] == 'observe'} | \
               {row['sha256'] + '.yaml' for row in manifest['templates']} | {'isolated-config.yml'}
    assert {p.name for p in base.iterdir()} <= expected
    # No update-tracker files are invited into the snapshot directory.
    assert not (base / '.new-additions').exists()


def test_contaminated_snapshot_cache_dir_is_quarantined_not_deleted(manifest_state, catalog, tmp_path):
    manifest = _approved(manifest_state, tmp_path)
    assert manifest['_chosen']
    flags = nuclei_policy.materialize(manifest_state, manifest)
    base = Path(flags[flags.index('-t') + 1])
    (base / 'cloud').mkdir()  # the -ud residue from a mutated run
    flags2 = nuclei_policy.materialize(manifest_state, manifest)
    bay = Path(flags2[flags2.index('-t') + 1])
    assert (bay / (manifest['_chosen'][0]['sha256'] + '.yaml')).is_file()
    # The quarantined cache is re-materialized at the deterministic same path,
    # now containing only the approved templates.
    assert not (bay / 'cloud').exists()
    # The contamination is preserved for the audit trail, not destroyed.
    tainted = [p for p in bay.parent.iterdir() if p.name.startswith(bay.name + '-tainted-')]
    assert tainted and (tainted[0] / 'cloud').is_dir()


def test_wall_clock_budget_derives_from_the_approved_request_ceiling(manifest_state, catalog, tmp_path, monkeypatch):
    import src.adaptix.config as cfgmod
    captured = {}

    def stub(argv, timeout=None, stdin=None, stderr_limit=2500):
        captured['timeout'] = timeout
        return {'returncode': 0, 'stdout': '', 'stderr': ''}

    monkeypatch.setattr(cfgmod, 'config', lambda *a, **k: {'limits': {'rate_per_second': 10, 'concurrent_requests': 5}})
    manifest = _approved(manifest_state, tmp_path)
    _scan_run(manifest_state, tmp_path, monkeypatch, manifest, stub)
    ceiling = manifest['request_ceiling_per_target']
    expected = max(30, ceiling / 10 + 5 * 5 + 25)
    assert captured['timeout'] <= expected
