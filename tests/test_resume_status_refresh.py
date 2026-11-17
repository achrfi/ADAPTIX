"""A resumed run must show ITS OWN status, not the one left behind by the attempt before it.

Reported bug: after /resume the UI kept displaying the previous run's status
(its last node / completed), so the resume looked like it had not started.
"""
import json
import os
import time

import pytest

from src.adaptix.ui.state import LiveView, view_from_state, view_from_progress
from src.adaptix.ui import screen as scr


# ---------------------------------------------------------------- progress file

def _runner(view, run_id='r1'):
    class FakeRunner(scr.Runner):
        def __init__(self):
            self.run_id = run_id
            self.resume_run_id = ''
            self.finished = type('E', (), {'clear': lambda s: None})()

        @property
        def running(self):
            return True

    r = FakeRunner()
    r.view = view
    return r


def _progress(tmp_path, name, node, phase, status, age_seconds=0.0):
    path = tmp_path / name
    path.write_text(json.dumps({'run_id': 'r1', 'node': node,
                                'phase': phase, 'status': status}), encoding='utf-8')
    if age_seconds:
        old = time.time() - age_seconds
        os.utime(path, (old, old))
    return path


def test_progress_written_before_the_resume_is_not_stale_for_a_fresh_view(tmp_path):
    """No start time recorded -> we cannot judge, so the file is trusted."""
    p = _progress(tmp_path, 'progress-1.json', 'final_report', 'completed',
                  'completed_partial', age_seconds=600)
    view = LiveView()
    view.started_at = 0
    assert _runner(view)._is_stale(str(tmp_path), json.loads(p.read_text())) is False


def test_progress_from_the_previous_attempt_is_detected_as_stale(tmp_path):
    _progress(tmp_path, 'progress-1.json', 'final_report', 'completed',
              'completed_partial', age_seconds=600)
    view = LiveView()
    view.started_at = time.time()          # the resume starts now
    data = json.loads((tmp_path / 'progress-1.json').read_text())
    assert _runner(view)._is_stale(str(tmp_path), data) is True


def test_progress_written_after_the_start_is_live(tmp_path):
    p = _progress(tmp_path, 'progress-1.json', 'web_discovery', 'running', 'running')
    view = LiveView()
    view.started_at = time.time() - 60     # started a minute ago; file is newer
    assert _runner(view)._is_stale(str(tmp_path), json.loads(p.read_text())) is False


def test_the_stale_file_is_what_would_have_overwritten_the_status(tmp_path):
    """The old behaviour, kept as a guard: applying it does hijack the view."""
    p = _progress(tmp_path, 'progress-1.json', 'final_report', 'completed',
                  'completed_partial', age_seconds=600)
    view = LiveView()
    view.workflow_node = 'baseline_reconnaissance'
    view.workflow_phase = 'running'
    view = view_from_progress(json.loads(p.read_text()), view)
    assert view.workflow_node == 'final_report'      # the bug
    assert view.workflow_phase == 'completed'


def test_skipping_the_stale_file_preserves_the_current_node(tmp_path):
    _progress(tmp_path, 'progress-1.json', 'final_report', 'completed',
              'completed_partial', age_seconds=600)
    view = LiveView()
    view.workflow_node = 'baseline_reconnaissance'
    view.workflow_phase = 'running'
    view.started_at = time.time()
    data = json.loads((tmp_path / 'progress-1.json').read_text())
    if not _runner(view)._is_stale(str(tmp_path), data):
        view = view_from_progress(data, view)
    assert view.workflow_node == 'baseline_reconnaissance'
    assert view.workflow_phase == 'running'


# ---------------------------------------------------------------- view_from_state

def test_a_resumed_snapshot_cannot_hijack_the_run_id():
    view = LiveView()
    view.run_id = 'the-run-the-operator-armed'
    view = view_from_state({'run_id': 'some-other-run', 'iterations': 4}, view)
    assert view.run_id == 'the-run-the-operator-armed'


def test_an_empty_view_still_learns_the_run_id_from_the_snapshot():
    view = LiveView()
    view.run_id = ''
    view = view_from_state({'run_id': 'learned'}, view)
    assert view.run_id == 'learned'


def test_the_pass_display_uses_the_live_counter_not_the_graph_counter():
    """Resume resets iterations_used; the graph counter keeps counting from before."""
    view = LiveView()
    state = {'iterations': 3, 'execution_metrics': {'iterations_used': 0}}
    view = view_from_state(state, view)
    assert view.iteration == 0


def test_the_live_counter_is_current_while_the_run_progresses():
    view = LiveView()
    state = {'iterations': 9, 'execution_metrics': {'iterations_used': 2}}
    view = view_from_state(state, view)
    assert view.iteration == 2


def test_a_snapshot_without_usage_metrics_falls_back_to_the_graph_counter():
    view = LiveView()
    view = view_from_state({'iterations': 5}, view)
    assert view.iteration == 5


def test_a_snapshot_with_no_iteration_field_keeps_what_the_view_had():
    view = LiveView()
    view.iteration = 7
    view = view_from_state({}, view)
    assert view.iteration == 7


# ---------------------------------------------------------------- checkpoint order

def test_checkpoints_are_chosen_by_mtime_not_by_name(tmp_path):
    """A resume rewrites checkpoint-0001..N, so name order can point into the past."""
    first = tmp_path / 'checkpoint-0001-aaaa.json'
    second = tmp_path / 'checkpoint-0002-bbbb.json'
    first.write_text('{"phase_runtime": [{"phase": "from-newer-file"}]}', encoding='utf-8')
    second.write_text('{"phase_runtime": [{"phase": "from-older-file"}]}', encoding='utf-8')
    now = time.time()
    os.utime(second, (now - 500, now - 500))   # lower name, older
    os.utime(first, (now, now))                # higher name, newer
    chosen = sorted(tmp_path.glob('checkpoint-*.json'), key=os.path.getmtime)[-1]
    assert chosen.name == 'checkpoint-0001-aaaa.json'


def test_the_old_name_ordering_would_have_picked_the_older_file(tmp_path):
    first = tmp_path / 'checkpoint-0001-aaaa.json'
    second = tmp_path / 'checkpoint-0002-bbbb.json'
    first.write_text('{}', encoding='utf-8')
    second.write_text('{}', encoding='utf-8')
    now = time.time()
    os.utime(second, (now - 500, now - 500))
    os.utime(first, (now, now))
    assert sorted(tmp_path.glob('checkpoint-*.json'))[-1].name == 'checkpoint-0002-bbbb.json'
