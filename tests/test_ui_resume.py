"""The screen must be able to continue a run it started, without a CLI hop.

Locked here: `/resume` is offered, the argv it builds actually carries the flag,
the resumed run keeps the id being continued (a fresh id would look up a
checkpoint that does not exist and silently start over), and the intent is
consumed so the next Enter is a new run.
"""
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.adaptix.ui.screen import Runner, HELP, resumable_runs  # noqa: E402


class _Proc:
    """Stands in for the child process: supports `with Popen(...)` and iteration."""

    returncode = 0
    stdout = []
    args = []

    def __init__(self, *args, **kwargs):
        self.args = args

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def poll(self):
        return 0

    def wait(self):
        return 0

    def communicate(self, *a, **kw):
        return ('', '')

    def kill(self):
        pass

    def terminate(self):
        pass


class _View:
    """The attributes Runner.command reads off the view."""

    def __init__(self, **over):
        self.context_tokens = 32768
        self.time_budget = 900
        self.tool_budget = 25
        self.token_budget = 200000
        self.max_iterations = 10
        self.target = ['http://127.0.0.1:3000']
        self.identity = ''
        self.model = ''
        self.run_id = ''
        self.objective = ''
        self.status = ''
        self.stop_reason = ''
        self.log = []
        self.started_at = 0.0
        for key, value in over.items():
            setattr(self, key, value)

    def append(self, *args, **kwargs):
        pass


def test_help_advertises_resume():
    assert '/resume' in HELP


def test_without_a_resume_the_command_starts_a_new_run():
    runner = Runner(_View())
    argv = runner.command('assess the lab')
    assert '--resume' not in argv


def test_resume_is_passed_through_to_the_engine():
    runner = Runner(_View())
    runner.resume_run_id = 'ui-120000'
    argv = runner.command('assess the lab')
    assert '--resume' in argv
    assert argv[argv.index('--resume') + 1] == 'ui-120000'


def test_a_resume_does_not_mint_a_new_run_id(monkeypatch):
    """A new id here is the bug: the checkpoint is looked up under it and not found."""
    view = _View()
    runner = Runner(view)
    runner.resume_run_id = 'ui-120000'

    started = {}

    def fake_popen(argv, **kwargs):
        started['argv'] = argv
        return _Proc()

    monkeypatch.setattr('subprocess.Popen', fake_popen)
    runner.start('assess the lab', str(ROOT))
    assert runner.run_id == 'ui-120000'
    assert view.run_id == 'ui-120000'


def test_a_fresh_run_still_generates_an_id(monkeypatch):
    view = _View()
    runner = Runner(view)

    monkeypatch.setattr('subprocess.Popen', lambda argv, **kw: _Proc())
    runner.start('assess the lab', str(ROOT))
    assert runner.run_id.startswith('ui-')
    assert runner.run_id != ''


def test_discovery_returns_a_list(tmp_path):
    """No artifacts directory is an empty answer, not an exception."""
    assert resumable_runs(str(tmp_path)) == []
