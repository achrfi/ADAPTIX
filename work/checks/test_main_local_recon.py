"""Main can start the fixed local inventory without entering the adaptive workflow."""
import importlib
import runpy
import sys
from unittest.mock import MagicMock

import pytest

from src.adaptix.local_inventory import cli as recon_cli

main_cli = importlib.import_module('src.adaptix.main')


@pytest.mark.parametrize('status', [0, 2])
def test_main_delegates_live_inventory_and_preserves_exit_status(monkeypatch, status):
    delegate = MagicMock(return_value=status)
    monkeypatch.setattr(recon_cli, 'main', delegate)
    monkeypatch.setattr(main_cli, 'authorize_cli_targets',
                        lambda *a: pytest.fail('Local recon must not enter the adaptive flow'))
    args = ['--target', 'http://127.0.0.1:3000', '--ai', '--out', 'work/run-check']
    assert main_cli.main(['--local-recon', *args]) == status
    delegate.assert_called_once_with(args)


def test_main_mode_flag_works_after_other_arguments(monkeypatch):
    delegate = MagicMock(return_value=0)
    monkeypatch.setattr(recon_cli, 'main', delegate)
    assert main_cli.main(['--target', 'http://127.0.0.1:3000', '--local-recon']) == 0
    delegate.assert_called_once_with(['--target', 'http://127.0.0.1:3000'])


def test_main_exposes_mode_in_help():
    assert '--local-recon' in main_cli.build_arg_parser().format_help()


@pytest.mark.parametrize('target', ['http://192.0.2.1:3000', 'http://127.0.0.1:3000/admin'])
def test_main_mode_cannot_bypass_local_scope_validation(monkeypatch, target):
    monkeypatch.setattr(recon_cli, 'run_local', lambda *a, **kw: pytest.fail('Invalid scope executed'))
    with pytest.raises(SystemExit) as result:
        main_cli.main(['--local-recon', '--target', target])
    assert result.value.code == 2


def test_adaptive_arguments_are_not_silently_used_in_local_recon(monkeypatch):
    monkeypatch.setattr(recon_cli, 'run_local', lambda *a, **kw: pytest.fail('Conflicting options executed'))
    with pytest.raises(SystemExit) as result:
        main_cli.main(['--local-recon', '--target', 'http://127.0.0.1:3000',
                       '--ffuf-results', 'previous.json'])
    assert result.value.code == 2


def test_unknown_provider_options_never_echo_credentials(capsys):
    with pytest.raises(SystemExit) as result:
        main_cli.main(['--local-recon', '--target', 'http://127.0.0.1:3000',
                       '--api-key', 'SYNTHETIC_PROVIDER_SECRET'])
    assert result.value.code == 2
    assert 'SYNTHETIC_PROVIDER_SECRET' not in capsys.readouterr().err


def test_package_entry_preserves_partial_run_exit_code(monkeypatch):
    monkeypatch.setattr(recon_cli, 'main', lambda *a: 2)
    monkeypatch.setattr(sys, 'argv', ['adaptix', '--local-recon', '--target', 'http://127.0.0.1:3000'])
    with pytest.raises(SystemExit) as result:
        runpy.run_module('src.adaptix', run_name='__main__')
    assert result.value.code == 2
