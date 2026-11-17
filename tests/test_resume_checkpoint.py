"""Resume must continue a stopped run, and must never authenticate with a marker.

Four defects were found by hand while building this; each test below fails on the
broken behaviour so it cannot come back.
"""

from src.adaptix.evidence.checkpoint import (KEY_MARKER, open_checkpoint,
                                             pending_nodes, resumable_snapshot,
                                             restore_runtime_secrets, thread_id_for,
                                             usable_key)
from src.adaptix.workflow.graph import resumable_graph


def _stopped_run(tmp_path, monkeypatch):
    """A run that hits its tool-call budget, so the thread ends with the stopping tail."""
    monkeypatch.setenv('ADAPTIX_TOKEN_BUDGET', '60000')
    from src.adaptix.workflow import graph as graph_module
    from src.adaptix.workflow.nodes import final_report
    state = {'run_id': 'resume-test', 'target': 'http://127.0.0.1:3000',
             'instruction': 'authorized self-test', 'tool_call_budget': 1,
             'token_budget': 60000, 'time_budget_seconds': 60,
             'max_iterations': 1, 'stop_reason': 'tool_call_budget_exhausted',
             'planned_actions': [], 'events': []}
    with open_checkpoint('resume-test', root=str(tmp_path)) as (saver, path):
        app = resumable_graph(saver)
        app.invoke(state, {'configurable': {'thread_id': thread_id_for('resume-test')}})
    return path


def test_a_marker_is_never_usable_as_a_key():
    """The checkpoint marker states a fact about the file; it is not a credential."""
    assert usable_key(KEY_MARKER) is None
    assert usable_key('') is None
    assert usable_key(None) is None
    assert usable_key('   ') is None
    assert usable_key('sk-real-value') == 'sk-real-value'


def test_restore_takes_the_key_from_the_environment_not_the_marker():
    """A resumed state holds a marker, so the key has to come from the environment."""
    state = {'llm_api_key': KEY_MARKER, 'run_id': 'x'}
    assert restore_runtime_secrets(state, env={'ADAPTIX_API_KEY': 'sk-from-env'})['llm_api_key'] == 'sk-from-env'
    assert restore_runtime_secrets(state, env={})['llm_api_key'] is None
    # A state that never had a marker is returned untouched.
    untouched = {'llm_api_key': 'sk-already'}
    assert restore_runtime_secrets(untouched, env={}) is untouched


def test_the_sanitizing_saver_keeps_the_key_out_of_the_file(tmp_path, monkeypatch):
    """The operator rule: no credential value may ever reach disk."""
    secret = 'sk-canary-must-not-appear-0123456789'
    monkeypatch.setenv('ADAPTIX_API_KEY', secret)
    state = {'run_id': 'secret-test', 'llm_api_key': secret, 'tool_call_budget': 1,
             'target': 'http://127.0.0.1:3000', 'events': []}
    with open_checkpoint('secret-test', root=str(tmp_path)) as (saver, path):
        app = resumable_graph(saver)
        app.invoke(state, {'configurable': {'thread_id': thread_id_for('secret-test')}})
    blob = open(path, 'rb').read()
    assert secret.encode() not in blob, 'the provider key reached the checkpoint file'
    assert KEY_MARKER.encode() in blob, 'the file should record that a key was redacted'


def test_control_versions_are_stored_verbatim(tmp_path, monkeypatch):
    """Scrubbing LangGraph's version counters made resume raise inside the saver."""
    monkeypatch.setenv('ADAPTIX_API_KEY', 'sk-whatever')
    state = {'run_id': 'version-test', 'tool_call_budget': 1,
             'target': 'http://127.0.0.1:3000', 'events': []}
    with open_checkpoint('version-test', root=str(tmp_path)) as (saver, path):
        app = resumable_graph(saver)
        cfg = {'configurable': {'thread_id': thread_id_for('version-test')}}
        app.invoke(state, cfg)
        # Reading history forces the saver to parse its own version tokens.
        history = list(app.get_state_history(cfg))
        assert history, 'no snapshots stored'
    assert 'REDACTED' not in open(path, 'rb').read().decode('latin-1'), \
        'a control field was scrubbed'


def test_a_stopped_run_reports_a_resumable_point(tmp_path, monkeypatch):
    """A finished thread ends on the stopping tail; the resumable point is the work step."""
    _stopped_run(tmp_path, monkeypatch)
    point = resumable_snapshot('resume-test', root=str(tmp_path))
    assert point is not None, 'a stopped run must report a resumable point'
    assert point.next != ('final_report',)


def test_resume_is_refused_without_a_checkpoint(tmp_path):
    assert pending_nodes('no-such-run', root=str(tmp_path)) == ()
    assert resumable_snapshot('no-such-run', root=str(tmp_path)) is None
