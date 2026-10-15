import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import pytest

from src.adaptix.agents import planner
from src.adaptix.agents.schema import PlannerDecision
from src.adaptix.agents.evidence_context import evidence_key
from src.adaptix.agents.action_identity import execution_identity
from src.adaptix.agents.review import grounded_review
from src.adaptix.agents.priority import record_outcome, observation_facts
from src.adaptix.security import nuclei_policy, authorization
from src.adaptix.security.action_policy import issue_action_approval


def model_response(payload):
    return SimpleNamespace(usage=SimpleNamespace(prompt_tokens=100, completion_tokens=30, total_tokens=130),
        choices=[SimpleNamespace(message=SimpleNamespace(content=json.dumps(payload)))])


@pytest.mark.parametrize('kind,count', [('http_services', 90), ('browser_evidence', 50), ('candidates', 90)])
def test_latest_evidence_survives_budget_compaction(kind, count, monkeypatch):
    captured = {}
    rows = [{'url': f'http://127.0.0.1/old-{i}', 'status_code': 200, 'title': 'old', 'template_id': f't-{i}',
             'text_excerpt': 'x' * 2000 if kind == 'browser_evidence' else ''} for i in range(count)]
    latest = {'url': 'http://127.0.0.1/latest-critical', 'status_code': 500, 'title': 'current', 'template_id': 'current'}
    rows.append(latest)
    def complete(**kwargs):
        captured.update(json.loads(kwargs['messages'][1]['content']))
        return model_response({'actions': [], 'reflection': 'Evaluate the new evidence and report limitations.', 'rationale': 'Audit'})
    monkeypatch.setattr(planner, 'tool_registry', lambda: {'httpx': {'enabled': True, 'path': 'mock'}})
    monkeypatch.setattr(planner.litellm, 'token_counter', lambda **kwargs: sum(len(m['content']) for m in kwargs['messages']) // 4)
    monkeypatch.setattr(planner.litellm, 'completion', complete)
    result = planner.adaptive_planning({'hosts': ['127.0.0.1'], kind: rows,
        'structured_observations': {kind: rows}, 'recent_evidence_keys': [evidence_key(kind, latest)]})
    assert captured['observations'][kind][0]['url'] == latest['url']
    assert any(row['url'] == latest['url'] for row in captured['observations'][kind])
    assert len(rows) == count + 1
    assert result['planner_metrics']['removed_context_records'] > 0


def test_nuclei_profile_change_allowed_but_identical_profile_still_blocked():
    target = 'http://127.0.0.1:18080/'
    action = {'tool': 'nuclei', 'target': target}
    state = {'hosts': ['127.0.0.1'], 'scope_ports': [18080], 'http_services': [{'url': target, 'tech': ['Nginx']}]}
    state['attempted_actions'] = [{**action, 'execution_identity': execution_identity(action, state)}]
    assert not planner._approved_actions(state, [action], {'nuclei'})
    state['http_services'] = [{'url': target, 'tech': ['WordPress', 'Nginx']}]
    assert planner._approved_actions(state, [action], {'nuclei'}) == [action]
    # Unrelated host technology cannot create a reason to repeat the same scan.
    state['http_services'] = [{'url': target, 'tech': ['Nginx']}, {'url': 'http://other.invalid/', 'tech': ['WordPress']}]
    assert not planner._approved_actions(state, [action], {'nuclei'})


@pytest.mark.parametrize('value', ['', ' ', '\n\t'])
def test_blank_reflection_rejected(value):
    with pytest.raises(ValueError):
        PlannerDecision(actions=[], reflection=value, rationale='Test')


def test_claimed_success_and_forged_evidence_do_not_override_ground_truth():
    decision = PlannerDecision.model_validate({'actions': [], 'reflection': 'The goal is achieved.', 'rationale': 'Test',
        'review': {'goal_status': 'achieved', 'evidence_refs': ['fabricated-evidence'], 'uncertainty': '', 'failure': '', 'decision_change': 'Stop'}})
    review, errors = grounded_review({'user_prompt': 'Uji IDOR dua identitas'}, decision)
    assert errors and review['goal_status'] != 'achieved'
    assert any('authenticated decisive proof' in error for error in errors)


def test_marginal_context_uses_projection_and_progress_is_goal_specific(monkeypatch):
    monkeypatch.setattr(planner.litellm, 'token_counter', lambda **kwargs: sum(len(m['content']) for m in kwargs['messages']) // 4)
    action = {'tool': 'httpx', 'target': 'http://127.0.0.1/'}
    result = {'http_services': [{'url': action['target'], 'status_code': 401, 'title': 'Login required', 'unforwarded_blob': 'x' * 30000}]}
    profiles, security = record_outcome({'user_prompt': 'Cari kerentanan'}, observation_facts({}), result, action, .1)
    _, status = record_outcome({'user_prompt': 'Periksa status HTTP dan judul'}, observation_facts({}), result, action, .1)
    assert security['goal_progress'] < status['goal_progress'] == 1
    assert security['context_tokens_estimate'] < 100
    assert security['context_token_measurement'] == 'projected_delta_tokenizer'


def template(path, method='GET', tags='tech,nginx', body=''):
    path.write_text(f'''id: audit-{path.stem}
info:
  name: Audit fixture
  author: audit
  severity: info
  tags: {tags}
http:
  - method: {method}
    path:
      - '{{{{BaseURL}}}}/audit-fixture'
{body}    matchers:
      - type: status
        status: [200]
''')
    return path


def test_exact_manifest_approval_post_and_snapshot_isolation(tmp_path, monkeypatch):
    monkeypatch.setattr(authorization, 'KEY_PATH', tmp_path / 'signing-key')
    authorization._key(create=True)
    get = template(tmp_path / 'get.yaml')
    post = template(tmp_path / 'post.yaml', 'POST')
    state = {'run_id': 'manifest-binding-test', 'principal': 'local-audit'}
    target = 'http://127.0.0.1:8080/'
    settings = {'nuclei_templates': [str(get), str(post)]}
    initial = nuclei_policy.prepare_scan(state, target, settings)
    assert initial['selected_count'] == 2 and initial['executable_count'] == 1
    assert initial['coverage'] == 'observation_subset'
    path = issue_action_approval(state['run_id'], state['principal'], 'nuclei', target, 'execute_manifest_once',
        destination=tmp_path / 'approval.json', manifest_sha256=initial['manifest_sha256'])
    permitted = nuclei_policy.prepare_scan({**state, 'action_approvals': [str(path)]}, target, settings)
    assert permitted['executable_count'] == 2
    approved_snapshot = nuclei_policy.materialize(state, permitted)
    default_snapshot = nuclei_policy.materialize(state, initial)
    assert approved_snapshot[1] != default_snapshot[1]
    assert len(list(Path(default_snapshot[1]).glob('*.yaml'))) == 1
    # Changing content invalidates the exact approval, even on the same file path.
    template(post, 'PUT')
    changed = nuclei_policy.prepare_scan({**state, 'action_approvals': [str(path)]}, target, settings)
    assert changed['approval']['result'] == 'denied' and changed['executable_count'] == 1
    with pytest.raises(ValueError, match='changed after manifest'):
        nuclei_policy.materialize(state, permitted)


def test_post_only_requires_approval_and_readonly_payload_is_not_trusted(tmp_path):
    post = template(tmp_path / 'post-only.yaml', 'POST')
    state = {'run_id': 'post-policy-test'}
    manifest = nuclei_policy.prepare_scan(state, 'http://127.0.0.1/', {'nuclei_templates': [str(post)]})
    assert manifest['executable_count'] == 0 and manifest['approval_required_count'] == 1
    raw = post.read_bytes().replace(b'POST', b'GET').replace(b'/audit-fixture', b'/{{interactsh-url}}')
    assert nuclei_policy.inspect_template(raw)['reasons']
    authority_escape = post.read_bytes().replace(b'POST', b'GET').replace(b'/audit-fixture', b'@other.invalid/')
    assert nuclei_policy.inspect_template(authority_escape)['reasons']
    match_only = post.read_bytes().replace(b'POST', b'GET').replace(b'type: status\n        status: [200]', b'type: word\n        name: interactsh\n        words: [interactsh]')
    assert not nuclei_policy.inspect_template(match_only)['reasons']


def test_reflection_feedback_can_correct_unfounded_success_before_any_tool(monkeypatch):
    from src.adaptix.workflow.graph import graph
    from src.adaptix.tools import registry
    target = 'http://127.0.0.1/'
    contexts, dispatched = [], []
    catalog = {'httpx': {'enabled': True, 'path': 'mock'}}
    monkeypatch.setattr(planner, 'tool_registry', lambda: catalog)
    monkeypatch.setattr(registry, 'tool_registry', lambda: catalog)
    action = {'tool': 'httpx', 'target': target, 'reason': 'Observe requested status',
              'priority': {'goal_relevance': 1, 'information_gain': 1, 'evidence_value': 1, 'confidence': 1,
                           'estimated_tokens': 10, 'estimated_seconds': .1, 'estimated_requests': 1}}
    def complete(**kwargs):
        context = json.loads(kwargs['messages'][1]['content']); contexts.append(context)
        index = len(contexts)
        if index == 1:
            payload = {'actions': [], 'reflection': 'Claimed success without evidence', 'rationale': 'Mistaken assumption',
                'review': {'goal_status': 'achieved', 'evidence_refs': [], 'uncertainty': '', 'failure': '', 'decision_change': 'Stop'}}
        elif index == 2:
            assert context['policy_feedback'] and not dispatched
            payload = {'actions': [action], 'reflection': 'No observation supports success; collect the HTTP status.', 'rationale': 'Correct the unsupported claim'}
        else:
            payload = {'actions': [], 'reflection': 'Status is now observed; stop.', 'rationale': 'Sufficient evidence',
                'review': {'goal_status': 'achieved', 'evidence_refs': [target], 'uncertainty': '', 'failure': '', 'decision_change': 'Stop after actual observation'}}
        return model_response(payload)
    def observe(state):
        dispatched.append(target)
        return {'http_services': [{'url': target, 'status_code': 200}], 'execution_metrics': {'tool_calls_used': 1}}
    monkeypatch.setattr(planner.litellm, 'completion', complete)
    monkeypatch.setattr(registry, 'tool_handlers', lambda: {'httpx': observe})
    result = graph.invoke({'target': [target], 'user_prompt': 'Periksa status HTTP', 'max_iterations': 5}, config={'recursion_limit': 100})
    assert len(contexts) == 3 and dispatched == [target]
    assert result['report']['objective_status'] == 'achieved'
    assert result['reflection_history'][0]['assessment']['validation_errors']
    assert not result['reflection_history'][-1]['assessment']['validation_errors']


def test_goal_completion_requires_all_named_scenarios_and_a_real_navigation_step(monkeypatch):
    from src.adaptix.agents import reflector
    findings = {'verified_findings': [{'scenario': 'one'}], 'rejected_findings': [], 'inconclusive_findings': []}
    monkeypatch.setattr(reflector, 'collect_findings', lambda state: findings)
    decision = PlannerDecision(actions=[], rationale='Review', reflection='Assess stored results')
    state = {'idor_scenarios': [{'name': 'one'}, {'name': 'two'}], 'user_prompt': 'Uji kedua skenario IDOR'}
    assert grounded_review(state, decision)[0]['goal_status'] != 'achieved'
    findings['verified_findings'].append({'scenario': 'two'})
    assert grounded_review(state, decision)[0]['goal_status'] == 'achieved'
    browser = {'user_prompt': 'Ikuti tautan detail', 'browser_evidence': [{'url': 'http://127.0.0.1/', 'title': 'Root', 'links': ['http://127.0.0.1/']}]}
    assert grounded_review(browser, decision)[0]['goal_status'] != 'achieved'
    browser['browser_evidence'][0]['links'].append('http://127.0.0.1/detail')
    browser['browser_evidence'].append({'url': 'http://127.0.0.1/detail', 'title': 'Detail'})
    assert grounded_review(browser, decision)[0]['goal_status'] == 'achieved'


def test_schema_retry_uses_safe_field_feedback_and_accounts_both_calls(monkeypatch):
    from src.adaptix.agents.decisions import request_decision
    seen = []
    def complete(**kwargs):
        seen.append(kwargs)
        content = {'actions': [], 'rationale': 'Review', 'reflection': 'Stored evidence is incomplete',
            'review': {'goal_status': 'uncertain', 'evidence_refs': [], 'uncertainty': 'Need evidence', 'failure': None, 'decision_change': 'Report the limitation'}}
        if len(seen) == 2:
            assert 'review.failure' in kwargs['messages'][-1]['content']
            content['review']['failure'] = ''
        return model_response(content)
    monkeypatch.setattr(planner.litellm, 'completion', complete)
    kwargs = {'model': 'test', 'messages': [{'role': 'user', 'content': 'Lab evidence'}], 'max_tokens': 512, 'timeout': 5}
    decision, metrics, _, ledger, error = request_decision({'planner_retry_limit': 1, 'token_budget': 2000}, kwargs, {}, 100)
    assert decision and not error and len(seen) == 2
    assert metrics['tokens_used'] == sum(row['tokens_charged'] for row in ledger) == 260
    assert ledger[0]['validation_fields'] == [{'field': 'review.failure', 'type': 'string_type'}]


def test_graph_retests_same_url_only_after_discovered_technology_changes(tmp_path, monkeypatch):
    from src.adaptix.workflow.graph import graph
    from src.adaptix.tools import nuclei, httpx, registry
    root = tmp_path / 'catalog'
    (root / 'http').mkdir(parents=True)
    template(root / 'http/nginx.yaml', tags='tech,nginx')
    template(root / 'http/wordpress.yaml', tags='tech,wordpress,wp')
    monkeypatch.setattr(nuclei_policy, 'template_root', lambda: root)
    catalog = {name: {'enabled': True, 'path': '/mock/' + name} for name in ('nuclei', 'httpx')}
    for module in (planner, registry, nuclei, httpx):
        monkeypatch.setattr(module, 'tool_registry', lambda: catalog)
    target = 'http://127.0.0.1:18080/'
    order, profiles = iter(['nuclei', 'httpx', 'nuclei', None]), []
    def complete(**kwargs):
        name = next(order)
        actions = [] if name is None else [{'tool': name, 'target': target, 'reason': 'Respond to technology evidence',
            'priority': {'goal_relevance': 1, 'information_gain': 1, 'evidence_value': 1, 'confidence': 1,
                         'estimated_tokens': 10, 'estimated_seconds': .1, 'estimated_requests': 1}}]
        return model_response({'actions': actions, 'reflection': 'Use the changed profile to select new tests.', 'rationale': 'Adaptive test'})
    monkeypatch.setattr(planner.litellm, 'completion', complete)
    def scan(argv, **kwargs):
        profiles.append(argv[argv.index('-tags') + 1])
        return {'returncode': 0, 'stdout': '', 'stderr': ''}
    monkeypatch.setattr(nuclei, 'run_tool', scan)
    monkeypatch.setattr(httpx, 'run_tool', lambda *a, **kw: {'returncode': 0, 'stdout': json.dumps({'url': target, 'status_code': 200, 'tech': ['WordPress'], 'webserver': 'nginx'}), 'stderr': ''})
    result = graph.invoke({'target': [target], 'max_iterations': 6, 'tool_call_budget': 6,
        'services': [{'host': '127.0.0.1', 'port': 18080, 'service': 'http', 'product': 'nginx'}]}, config={'recursion_limit': 100})
    assert profiles == ['nginx', 'nginx,wordpress,wp']
    assert [row['tool'] for row in result['attempted_actions']] == ['nuclei', 'httpx', 'nuclei']


def test_stop_decision_schema_repair_explains_nonempty_next_choice(monkeypatch):
    from src.adaptix.agents.decisions import request_decision
    calls = []
    def complete(**kwargs):
        calls.append(kwargs)
        next_choice = ''
        if len(calls) == 2:
            assert 'review.decision_change' in kwargs['messages'][-1]['content']
            assert 'including stopping' in kwargs['messages'][-1]['content']
            next_choice = 'Stop and report the unresolved limitation'
        return model_response({'actions': [], 'rationale': 'Review', 'reflection': 'There is no valid authentication evidence',
            'review': {'goal_status': 'uncertain', 'evidence_refs': [], 'uncertainty': 'Authentication unavailable',
                       'failure': '', 'decision_change': next_choice}})
    monkeypatch.setattr(planner.litellm, 'completion', complete)
    decision, metrics, _, ledger, error = request_decision({'planner_retry_limit': 1, 'token_budget': 4000},
        {'model': 'test', 'messages': [{'role': 'user', 'content': 'Lab'}], 'max_tokens': 512, 'timeout': 5}, {}, 50)
    assert decision and not error and len(calls) == 2
    assert metrics['tokens_used'] == sum(row['tokens_charged'] for row in ledger) == 260


def test_self_link_refresh_and_repeated_uncertainty_are_not_new_progress(monkeypatch):
    from src.adaptix.agents.progress import progress_assessment
    from src.adaptix.agents import reflector
    target = 'http://127.0.0.1/'
    state = {'user_prompt': 'Ikuti tautan detail', 'browser_evidence': [{'url': target, 'title': 'Old', 'links': [target]}]}
    assert progress_assessment(state, {'browser_evidence': [{'url': target, 'title': 'New'}]})['goal_progress'] < 1
    monkeypatch.setattr(reflector, 'collect_findings', lambda state: {'verified_findings': [], 'rejected_findings': [],
        'inconclusive_findings': [{'target': target, 'template_id': 'idor-test'}]})
    assert progress_assessment({'user_prompt': 'Uji IDOR'}, {})['goal_progress'] == 0


def test_native_schema_and_specific_navigation_recovery_feedback(monkeypatch):
    captured = {}
    target = 'http://127.0.0.1/'
    decision = PlannerDecision.model_validate({'actions': [], 'reflection': 'Mistakenly claimed page was visited', 'rationale': 'Review',
        'review': {'goal_status': 'achieved', 'evidence_refs': [target], 'uncertainty': '', 'failure': '', 'decision_change': 'Stop'}})
    state = {'user_prompt': 'Ikuti tautan detail', 'browser_evidence': [{'url': target, 'links': [target + 'detail'], 'title': 'Root'}]}
    review, feedback = grounded_review(state, decision)
    assert any('A discovered link is not a visited page' in error for error in feedback)
    def complete(**kwargs):
        captured.update(kwargs)
        return model_response({'actions': [], 'reflection': 'Destination still needs observation', 'rationale': 'Review'})
    monkeypatch.setattr(planner, 'tool_registry', lambda: {'playwright': {'enabled': True, 'path': 'mock'}})
    monkeypatch.setattr(planner.litellm, 'completion', complete)
    planner.adaptive_planning({**state, 'hosts': ['127.0.0.1'], 'reflection_assessment': review,
        'planner_metrics': {'self_reflection': 'The destination was visited'}, 'policy_feedback': [{'reason': error} for error in feedback]})
    payload = json.loads(captured['messages'][1]['content'])
    assert 'rejected by the evidence controller' in payload['previous_self_reflection']
    assert payload['controller_assessment']['goal_status'] == 'in_progress'
    schema = captured['response_format']['json_schema']['schema']
    assert 'review' in schema['required'] and schema['properties']['review'] == {'$ref': '#/$defs/ReflectionReview'}
    assert '$defs' not in captured['messages'][0]['content']
