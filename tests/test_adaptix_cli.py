import sys
from unittest.mock import MagicMock
from src.adaptix.main import main
import importlib
cli = importlib.import_module('src.adaptix.main')
from src.adaptix.workflow.graph import graph


def test_instruction_reaches_planner_state_unchanged(monkeypatch, capsys):
    instruction = 'Periksa kontrol akses API. Jelaskan bukti, kegagalan, dan langkah berikutnya.'
    invoke = MagicMock(return_value={'report': {}, 'events': []})
    monkeypatch.setattr(graph, 'invoke', invoke)
    monkeypatch.setattr(cli, 'authorize_cli_targets', lambda *a: ('operator-grant.json', 'operator'))
    monkeypatch.setattr(sys, 'argv', ['adaptix', '--instruction', instruction,
                                    '--target', '127.0.0.1'])
    main()
    state = invoke.call_args.args[0]
    assert state['user_prompt'] == instruction
    assert state['target'] == ['127.0.0.1']
    assert 'authorization_confirmed' not in state
    assert state['grant'] == 'operator-grant.json'


def test_cli_exposes_context_budget_and_sampling(monkeypatch):
    invoke = MagicMock(return_value={'report': {}, 'events': []})
    monkeypatch.setattr(graph, 'invoke', invoke)
    monkeypatch.setattr(cli, 'authorize_cli_targets', lambda *a: ('operator-grant.json', 'operator'))
    monkeypatch.setattr(sys, 'argv', ['adaptix', '--instruction', 'Observe', '--target', '127.0.0.1',
                                    '--model-context-tokens', '2048', '--temperature', '0.1'])
    main()
    state = invoke.call_args.args[0]
    assert state['model_context_tokens'] == 2048 and state['llm_temperature'] == 0.1


def test_cli_help_has_no_authorized_flag(monkeypatch,capsys):
    import pytest
    monkeypatch.setattr(sys,'argv',['adaptix','--help'])
    with pytest.raises(SystemExit) as exc: main()
    assert exc.value.code==0
    assert '--authorized' not in capsys.readouterr().out
