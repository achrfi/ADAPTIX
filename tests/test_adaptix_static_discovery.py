"""Static content discovery (ffuf): scope, calibration and signal quality.

The failure these tests pin down: a target that answers unknown paths with a
custom error page (500) or an SPA shell (200) used to fill the route inventory
with paths that do not exist, so the planner spent the whole budget on them and
the run reported zero findings on a lab full of bugs.
"""
import json

import pytest

from src.adaptix.tools import static_discovery as sd
from src.adaptix.security.authorization import authorize_cli_targets

# This module exercises the real adapter, so the suite-wide "no live sweep" fixture
# (tests/conftest.py) must not replace it with the inert stub.
_REAL = sd.static_discovery


@pytest.fixture(autouse=True)
def _restore_real_adapter(monkeypatch):
    monkeypatch.setattr(sd, 'static_discovery', _REAL)


def _state(target='http://127.0.0.1:18080', **over):
    grant, principal = authorize_cli_targets([target], hours=1)
    state = {'target': [target], 'grant': grant, 'principal': principal,
             'run_id': 't-static', 'events': [], 'errors': [],
             'hosts': ['127.0.0.1'], 'scope_aliases': [], 'scope_networks': [],
             'planned_actions': [{'tool': 'static_discovery', 'target': target}],
             'web_routes': [], 'discovered_documents': [], 'discovery_limitations': [],
             'execution_metrics': {}, 'raw_bytes': 0, 'status': 'scope_ok'}
    state.update(over)
    return state


# --- calibration ------------------------------------------------------------

def test_error_signature_records_skeleton_length_for_a_path_echoing_template():
    body = b'<title>Error: Unexpected path: /api/adaptix-canary-abc</title>' \
           b'<h2>500 Error: Unexpected path: /api/adaptix-canary-abc</h2>'
    probe = {'status': 500, 'length': len(body), 'body': body,
             'path': '/api/adaptix-canary-abc', 'token': 'abc', 'prefix': '/api'}
    sig = sd._error_signature(probe)
    # The path is echoed twice, so the skeleton is length - 2 * len(path).
    assert sig['echoes'] == 2
    assert sig['base'] == len(body) - 2 * len('/api/adaptix-canary-abc')


def test_a_sibling_of_the_canary_is_recognised_by_arithmetic():
    """The whole point: a *different* nonexistent path must also be filtered."""
    canary_path = '/api/adaptix-canary-abc'
    base = 2400
    sig = {'status': 500, 'base': base, 'echoes': 2, 'length': base + 2 * len(canary_path),
           'prefix': '/api', 'path': canary_path}
    other = '/api/nonexistent-thing'
    row = {'status': 500, 'length': base + 2 * len(other), '_path': other}
    assert sd._is_canary_echo(row, [sig]) is True


def test_a_genuinely_different_response_is_not_filtered():
    sig = {'status': 500, 'base': 2400, 'echoes': 2, 'length': 2400 + 2 * len('/api/x'),
           'prefix': '/api', 'path': '/api/x'}
    # A real endpoint answering with a different body length must survive.
    assert sd._is_canary_echo({'status': 500, 'length': 9999, '_path': '/api/real'},
                              [sig]) is False
    # Same length but a different status is a different response class.
    assert sd._is_canary_echo({'status': 200, 'length': 2400 + 2 * len('/api/x'),
                               '_path': '/api/x'}, [sig]) is False


def test_constant_length_soft_404_is_filtered_by_length_alone():
    sig = {'status': 200, 'base': None, 'echoes': 0, 'length': 9984,
           'prefix': '', 'path': '/adaptix-canary-abc'}
    assert sd._is_canary_echo({'status': 200, 'length': 9984, '_path': '/anything'}, [sig]) is True
    assert sd._is_canary_echo({'status': 200, 'length': 1234, '_path': '/anything'}, [sig]) is False


def test_signature_without_a_body_degrades_to_length_only():
    sig = sd._error_signature({'status': 404, 'length': 0, 'body': b'', 'path': '/x',
                               'token': 'x', 'prefix': ''})
    assert sig['base'] is None and sig['length'] == 0


# --- scope and safety -------------------------------------------------------

def test_out_of_scope_origin_is_refused_before_any_process_starts(monkeypatch):
    """Scope is enforced twice: at grant time and again inside the adapter."""
    # A host outside the granted scope cannot even obtain a grant (DNS/allowlist
    # refusal happens before the process starts), and an adapter call whose target
    # was swapped after authorization is refused by the adapter's own check.
    with pytest.raises(ValueError):
        authorize_cli_targets(['http://evil.example.com'], hours=1)

    def explode(*a, **k):
        raise AssertionError('an out-of-scope target must never reach the subprocess')
    monkeypatch.setattr(sd, '_ffuf_binary', lambda: '/usr/bin/ffuf')
    monkeypatch.setattr(sd, '_reachable', lambda *a, **k: True)
    monkeypatch.setattr(sd.subprocess, 'run', explode)
    out = sd.static_discovery(_state(planned_actions=[{
        'tool': 'static_discovery', 'target': 'http://evil.example.com:18080'}]))
    assert out['errors'] and 'outside pinned scope' in out['errors'][0]


def test_non_absolute_target_is_refused():
    out = sd.static_discovery(_state(planned_actions=[{'tool': 'static_discovery', 'target': '/api'}]))
    assert 'absolute URL' in out['errors'][0]


def test_unreachable_origin_is_a_recorded_limitation_not_an_error(monkeypatch):
    monkeypatch.setattr(sd, '_ffuf_binary', lambda: '/usr/bin/ffuf')
    monkeypatch.setattr(sd, '_reachable', lambda *a, **k: False)
    out = sd.static_discovery(_state())
    assert out['discovery_limitations'][-1]['reason'] == 'origin_unreachable'
    assert 'errors' not in out


def test_missing_binary_records_a_limitation(monkeypatch):
    monkeypatch.setattr(sd, '_ffuf_binary', lambda: None)
    out = sd.static_discovery(_state())
    assert out['discovery_limitations'][-1]['reason'] == 'ffuf_unavailable'


def test_wordlist_path_outside_the_project_tree_is_refused():
    with pytest.raises(ValueError):
        sd._valid_wordlist('common', '/etc/passwd')


def test_each_profile_resolves_to_its_own_wordlist():
    names = {sd._valid_wordlist(name, None).name for name in sd.PROFILES}
    assert len(names) == len(sd.PROFILES), 'profiles must not collapse onto one file'


def test_shipped_wordlists_exist_and_are_non_empty():
    for name in sd.PROFILES:
        path = sd._valid_wordlist(name, None)
        words, total = sd._wordlist(path)
        assert words and total >= len(words)


# --- result handling --------------------------------------------------------

def test_matches_become_routes_and_the_canary_echo_is_dropped(monkeypatch, tmp_path):
    canary_path = '/api/adaptix-canary-abc'
    base = 2410
    payload = {'results': [
        {'url': 'http://127.0.0.1:18080/api/real', 'status': 401, 'length': 972,
         'method': 'GET', 'words': 10},
        {'url': f'http://127.0.0.1:18080{canary_path}', 'status': 500,
         'length': base + 2 * len(canary_path), 'method': 'GET', 'words': 5},
        {'url': 'http://127.0.0.1:18080/api/zzz-nonexistent', 'status': 500,
         'length': base + 2 * len('/api/zzz-nonexistent'), 'method': 'GET', 'words': 5},
    ]}
    out_file = tmp_path / 'ffuf.json'
    out_file.write_text(json.dumps(payload), encoding='utf-8')

    monkeypatch.setattr(sd, '_ffuf_binary', lambda: '/usr/bin/ffuf')
    monkeypatch.setattr(sd, '_reachable', lambda *a, **k: True)
    monkeypatch.setattr(sd, '_calibrate', lambda origin, prefix, timeout=4: {
        'status': 500, 'base': base, 'echoes': 2,
        'length': base + 2 * len(canary_path), 'prefix': prefix, 'path': canary_path})
    monkeypatch.setattr(sd, 'artifact_path', lambda *a, **k: out_file)
    monkeypatch.setattr(sd, 'save_text', lambda path, text: None)
    monkeypatch.setattr(sd.subprocess, 'run', lambda *a, **k: type(
        'R', (), {'stdout': '', 'stderr': '', 'returncode': 0})())

    out = sd.static_discovery(_state())
    urls = [r['url'] for r in out['web_routes']]
    assert urls == ['http://127.0.0.1:18080/api/real']
    assert out['static_discovery']['rejected_soft_404'] == 2
    assert out['static_discovery']['profile'] == sd.DEFAULT_PROFILE
    assert out['static_swept'] == [sd.DEFAULT_PROFILE]


def test_a_nonzero_exit_without_output_is_recorded_not_faked(monkeypatch, tmp_path):
    missing = tmp_path / 'never-written.json'
    monkeypatch.setattr(sd, '_ffuf_binary', lambda: '/usr/bin/ffuf')
    monkeypatch.setattr(sd, '_reachable', lambda *a, **k: True)
    monkeypatch.setattr(sd, '_calibrate', lambda *a, **k: None)
    monkeypatch.setattr(sd, 'artifact_path', lambda *a, **k: missing)
    monkeypatch.setattr(sd, 'save_text', lambda path, text: None)
    monkeypatch.setattr(sd.subprocess, 'run', lambda *a, **k: type(
        'R', (), {'stdout': '', 'stderr': 'boom', 'returncode': 2})())
    out = sd.static_discovery(_state())
    assert any('exit 2' in e for e in out['errors'])
    assert 'web_routes' not in out
    assert out['discovery_limitations'][-1]['reason'] == 'ffuf_failed'


def test_ffuf_argv_is_pinned_to_the_authorized_origin_with_no_shell(monkeypatch, tmp_path):
    seen = {}

    def capture(argv, **kwargs):
        seen['argv'] = argv
        seen['kwargs'] = kwargs
        raise OSError('stop here')
    payload = tmp_path / 'out.json'
    monkeypatch.setattr(sd, '_ffuf_binary', lambda: '/usr/bin/ffuf')
    monkeypatch.setattr(sd, '_reachable', lambda *a, **k: True)
    monkeypatch.setattr(sd, '_calibrate', lambda *a, **k: None)
    monkeypatch.setattr(sd, 'artifact_path', lambda *a, **k: payload)
    monkeypatch.setattr(sd, 'save_text', lambda path, text: None)
    monkeypatch.setattr(sd.subprocess, 'run', capture)
    sd.static_discovery(_state())
    argv = seen['argv']
    assert seen['kwargs'].get('shell') is False
    assert 'http://127.0.0.1:18080/FUZZ' in argv
    # No shell metacharacter can reach a real shell, and no credential env leaks in.
    assert not any(str(a).startswith('--wordlist=') for a in argv)
    env = seen['kwargs']['env']
    assert not any(k.upper().endswith(('TOKEN', 'KEY', 'SECRET', 'PASSWORD')) for k in env)
