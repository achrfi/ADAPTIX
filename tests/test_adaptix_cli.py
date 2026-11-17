import sys
from unittest.mock import MagicMock
from src.adaptix.main import main
import importlib
cli = importlib.import_module('src.adaptix.main')
from src.adaptix.workflow.graph import graph


def _run_and_capture_state(monkeypatch, argv):
    """Run the CLI and return the state the graph was asked to execute.

    Day 2 made a run stream through an engine bound to its checkpoint, so the state is
    captured at the graph boundary instead of by patching ``graph.stream``: what matters
    is that the operator's state reaches the graph unchanged, not which attribute the
    CLI happens to call.
    """
    captured = {}

    def _capture(engine, state, config, cancelled, seed=None):
        captured['state'] = state
        captured['config'] = config
        return {'report': {}, 'events': []}

    monkeypatch.setattr(cli, 'run_stream', _capture)
    monkeypatch.setattr(cli, 'authorize_cli_targets',
                        lambda *a, **k: ('operator-grant.json', 'operator'))
    monkeypatch.setattr(sys, 'argv', argv)
    main()
    return captured['state']


def test_instruction_reaches_planner_state_unchanged(monkeypatch, capsys):
    instruction = 'Periksa kontrol akses API. Jelaskan bukti, kegagalan, dan langkah berikutnya.'
    state = _run_and_capture_state(
        monkeypatch, ['adaptix', '--instruction', instruction, '--target', '127.0.0.1'])
    assert state['user_prompt'] == instruction
    assert state['target'] == ['127.0.0.1']
    assert 'authorization_confirmed' not in state
    assert state['grant'] == 'operator-grant.json'


def test_cli_exposes_context_budget_and_sampling(monkeypatch):
    state = _run_and_capture_state(
        monkeypatch, ['adaptix', '--instruction', 'Observe', '--target', '127.0.0.1',
                      '--model-context-tokens', '2048', '--temperature', '0.1'])
    assert state['model_context_tokens'] == 2048 and state['llm_temperature'] == 0.1


def test_cli_help_has_no_authorized_flag(monkeypatch,capsys):
    import pytest
    monkeypatch.setattr(sys,'argv',['adaptix','--help'])
    with pytest.raises(SystemExit) as exc: main()
    assert exc.value.code==0
    assert '--authorized' not in capsys.readouterr().out
