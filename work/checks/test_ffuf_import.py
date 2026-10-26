"""Operator JSON -> scope -> observations -> planner -> report, without tool execution."""
import importlib
import json
from pathlib import Path
import sys
from unittest.mock import MagicMock

import pytest

from src.adaptix.agents import planner
from src.adaptix.agents.capabilities import endpoint_provenance
from src.adaptix.evidence import audit, storage
from src.adaptix.processing.ffuf import (
    CONTEXT_ROWS, MAX_FILE_BYTES, MAX_IMPORTS, MAX_RESULTS, load_ffuf_files,
)
from src.adaptix.processing.observations import observation_processing
from src.adaptix.workflow.graph import graph
from src.adaptix.workflow.nodes import execute_action, scope_guard

BASE = 'http://127.0.0.1:3000'


def write_input(tmp_path, rows=None, **extra):
    path = tmp_path / 'operator.json'
    data = {'results': rows if rows is not None else [
        {'url': BASE + '/admin', 'status': 200, 'length': 100, 'words': 10, 'lines': 2}],
        'config': {'method': 'GET'}, **extra}
    path.write_text(json.dumps(data))
    return path


def imported(path, **extra):
    state = {'target': [BASE], 'ffuf_import_documents': load_ffuf_files([path]), **extra}
    return {**state, **scope_guard(state)}


def test_scope_filter_redaction_and_deduplication(tmp_path):
    row = {'url': BASE + '/admin?api_key=synthetic-secret', 'status': 200}
    path = write_input(tmp_path, [row, row,
        {'url': 'http://outside.invalid/admin', 'status': 200},
        {'url': 'http://127.0.0.1:9999/admin', 'status': 200},
        {'url': BASE + '/invalid', 'status': True},
        {'url': 'http://user:password@127.0.0.1:3000/', 'status': 200}],
        commandline='SECRET_COMMAND_LINE', config={'method': 'GET', 'headers': {'Cookie': 'SECRET_COOKIE'}})
    state = imported(path)
    assert state['status'] == 'scope_ok'
    assert len(state['ffuf_observations']) == 1
    assert state['ffuf_imports'][0]['duplicate_rows'] == 1
    assert state['ffuf_imports'][0]['rejection_counts'] == {'outside_scope': 2, 'invalid_record': 2}
    assert state['ffuf_import_documents'] == []
    assert 'synthetic-secret' not in json.dumps(state)
    assert 'SECRET_COOKIE' not in json.dumps(state)
    assert 'SECRET_COMMAND_LINE' not in json.dumps(state)
    assert state['operator_recon_review_only'] is True
    assert state['baseline_disabled'] and state['scanner_disabled']


@pytest.mark.parametrize('content', ['{', '[]', '{"results":{}}',
    '{"results":[],"results":[]}', '{"results":[],"number":NaN}'])
def test_invalid_or_ambiguous_json_is_rejected(tmp_path, content):
    path = tmp_path / 'invalid.json'
    path.write_text(content)
    with pytest.raises(ValueError):
        load_ffuf_files([path])


def test_input_limits_are_enforced(tmp_path):
    path = tmp_path / 'large.json'
    path.write_bytes(b' ' * (MAX_FILE_BYTES + 1))
    with pytest.raises(ValueError):
        load_ffuf_files([path])
    path = write_input(tmp_path, [None] * (MAX_RESULTS + 1))
    with pytest.raises(ValueError):
        load_ffuf_files([path])
    with pytest.raises(ValueError):
        load_ffuf_files([path] * (MAX_IMPORTS + 1))


def test_duplicate_file_does_not_duplicate_import_or_observations(tmp_path):
    path = write_input(tmp_path)
    documents = load_ffuf_files([path, path])
    state = scope_guard({'target': [BASE], 'ffuf_import_documents': documents})
    assert len(state['ffuf_imports']) == len(state['ffuf_observations']) == 1


def test_empty_results_remain_empty_evidence(tmp_path):
    state = imported(write_input(tmp_path, []))
    assert state['ffuf_imports'][0]['input_rows'] == 0
    assert state['ffuf_observations'] == []
    assert state['structured_observations']['ffuf_observations'] == []


def test_import_does_not_promote_routes_or_consume_tool_budget(tmp_path):
    state = imported(write_input(tmp_path))
    state.update(observation_processing(state))
    assert len(state['structured_observations']['ffuf_observations']) == 1
    assert state.get('web_routes', []) == []
    assert state.get('http_services', []) == []
    assert not any(BASE + '/admin' in row['urls'] for row in endpoint_provenance(state).values())
    assert state['metrics']['tool_calls_used'] == 0


@pytest.mark.parametrize('review_state', [
    {'operator_recon_review_only': True}, {'ffuf_import_documents': [{}]},
    {'ffuf_imports': [{}]}, {'ffuf_observations': [{}]},
])
def test_execution_boundary_refuses_actions_in_review_mode(monkeypatch, review_state):
    from src.adaptix.tools import registry
    monkeypatch.setattr(registry, 'tool_handlers', lambda: pytest.fail('No dispatch is allowed'))
    result = execute_action({**review_state,
                             'planned_actions': [{'tool': 'ffuf', 'target': BASE}]})
    assert result['planned_actions'] == []
    assert result['stop_reason'] == 'operator_recon_review_only'


def test_graph_scope_does_not_accept_normalized_output_as_import_input():
    result = scope_guard({'target': [BASE], 'ffuf_observations': [
        {'url': 'http://outside.invalid/unvalidated', 'status_code': 200}]})
    assert result['status'] == 'scope_blocked'
    assert 'ffuf_import_documents' in result['errors'][0]


@pytest.fixture
def review_run(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, 'ROOT', tmp_path)
    monkeypatch.setattr(audit, 'ROOT', tmp_path)
    from src.adaptix.tools import registry
    monkeypatch.setattr(registry, 'tool_handlers', lambda: pytest.fail('Imported evidence must not dispatch tools'))
    monkeypatch.setattr(planner.litellm, 'token_counter', lambda **kwargs: 100)
    captured = []

    def completion(**kwargs):
        payload = json.loads(kwargs['messages'][1]['content'])
        captured.append(payload)
        response = {'actions': [], 'rationale': 'Review operator-provided observations only',
                    'reflection': 'Recorded HTTP responses do not establish routes or vulnerabilities.',
                    'hypotheses': [], 'review': {'goal_status': 'uncertain', 'evidence_refs': [],
                        'uncertainty': 'No independent route verification or missing-path control was imported.',
                        'failure': '', 'decision_change': 'Stop and report the supplied evidence and limitations.'}}
        return MagicMock(choices=[MagicMock(message=MagicMock(content=json.dumps(response)))],
                         usage=MagicMock(prompt_tokens=100, completion_tokens=50, total_tokens=150))

    monkeypatch.setattr(planner.litellm, 'completion', completion)

    def run(rows):
        path = write_input(tmp_path, rows)
        result = graph.invoke({'target': [BASE], 'run_id': 'operator-import-test',
            'ffuf_import_documents': load_ffuf_files([path]),
            'user_prompt': 'Describe the supplied ffuf evidence and its limitations.',
            'max_iterations': 1, 'token_budget': 6000, 'model_context_tokens': 8192,
            'time_budget_seconds': 180, 'tool_call_budget': 2, 'errors': [], 'events': []},
            config={'recursion_limit': 30})
        return result, captured
    return run


def test_complete_graph_retains_import_in_state_prompt_report_and_bundle(review_run):
    result, captured = review_run([{'url': BASE + '/admin', 'status': 200, 'length': 100}])
    assert len(captured) == 1
    payload = captured[0]
    assert payload['tool_registry'] == {}
    assert payload['observations']['ffuf_observations'][0]['status_code'] == 200
    assert payload['ffuf_import_summary']['observations'] == 1
    assert payload['observations']['ffuf_observations'][0]['evidence_ref'].startswith('ffuf_observations:')
    assert result['structured_observations']['ffuf_observations'] == result['ffuf_observations']
    assert result['report']['ffuf_observations'] == result['ffuf_observations']
    assert result['report']['ffuf_imports'] == result['ffuf_imports']
    assert result['verified_findings'] == []
    assert result['metrics']['tool_calls_used'] == 0
    assert 'Operator-imported ffuf observations (1)' in result['markdown_report']
    assert 'ffuf-imports' in result['artifact_bundle']
    assert 'SECRET' not in json.dumps(result)


def test_model_context_is_sampled_while_full_import_stays_in_report(review_run):
    rows = [{'url': BASE + f'/route-{i}', 'status': 200} for i in range(CONTEXT_ROWS + 5)]
    result, captured = review_run(rows)
    assert len(captured[0]['observations']['ffuf_observations']) == CONTEXT_ROWS
    assert captured[0]['ffuf_import_summary']['observations'] == len(rows)
    assert len(result['report']['ffuf_observations']) == len(rows)


def test_cli_loads_only_safe_fields_into_graph_input(tmp_path, monkeypatch, capsys):
    cli = importlib.import_module('src.adaptix.main')
    path = write_input(tmp_path, commandline='SECRET_COMMAND')
    stream = MagicMock(return_value=iter([{'report': {}, 'events': []}]))
    monkeypatch.setattr(graph, 'stream', stream)
    monkeypatch.setattr(cli, 'authorize_cli_targets', lambda *args: ('test-grant', 'test-operator'))
    monkeypatch.setattr(sys, 'argv', ['adaptix', '--instruction', 'Review imported results',
        '--target', BASE, '--ffuf-results', str(path)])
    cli.main()
    state = stream.call_args.args[0]
    assert len(state['ffuf_import_documents']) == 1
    assert 'SECRET_COMMAND' not in json.dumps(state)
