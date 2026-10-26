"""LangGraph node progress is the dashboard's live status source."""
import json

from src.adaptix.workflow import progress


def test_progress_records_node_and_phase_without_state_secrets(tmp_path, monkeypatch):
    target = tmp_path / 'progress.json'
    monkeypatch.setattr(progress, 'artifact_path',
                        lambda state, stage, host, suffix: target)
    state = {'run_id': 'r1', 'status': 'scope_ok', 'iterations': 2,
             'run_started_at': 100.0, 'llm_api_key': 'sk-secret'}
    path = progress.write_progress(state, 'adaptive_planning', 'running',
                                   started_at=101.0, event='Planning: one action')
    payload = json.loads(path.read_text())
    assert payload['node'] == 'adaptive_planning'
    assert payload['phase'] == 'running'
    assert payload['iteration'] == 2
    assert payload['event'] == 'Planning: one action'
    assert 'llm_api_key' not in payload
    assert 'sk-secret' not in path.read_text()


def test_progress_is_atomic_and_keeps_only_the_latest_node(tmp_path, monkeypatch):
    target = tmp_path / 'progress.json'
    monkeypatch.setattr(progress, 'artifact_path',
                        lambda state, stage, host, suffix: target)
    state = {'run_id': 'r1', 'status': 'scope_ok'}
    progress.write_progress(state, 'nuclei_scan', 'running')
    progress.write_progress(state, 'nuclei_scan', 'completed', duration=1.5,
                            event='Nuclei Scan: complete')
    payload = json.loads(target.read_text())
    assert payload['phase'] == 'completed'
    assert payload['node_seconds'] == 1.5
    assert not list(tmp_path.glob('*.tmp'))


def test_timed_graph_node_writes_running_and_completed_phases(monkeypatch):
    from src.adaptix.workflow import graph as graph_module

    calls = []
    monkeypatch.setattr(graph_module, 'write_progress',
                        lambda state, node, phase, **kwargs: calls.append((node, phase, kwargs)))
    wrapped = graph_module._timed('adaptive_planning',
                                  lambda state: {'events': ['Adaptive Planning: done']})
    result = wrapped({'run_id': 'r1', 'iterations': 1, 'events': ['started']})
    assert result['phase_runtime'][0]['phase'] == 'adaptive_planning'
    assert [row[:2] for row in calls] == [('adaptive_planning', 'running'),
                                          ('adaptive_planning', 'completed')]
    assert calls[-1][2]['event'] == 'Adaptive Planning: done'
