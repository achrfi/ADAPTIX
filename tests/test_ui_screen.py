"""Drive the real draw() with a recording fake window and assert the layout.

Why a fake instead of a pty: a pty dump loses the row/column coordinates, and the two
things the operator asked for are exactly positional - the prompt is the bottom line and
the token meter sits above it. This records every write as (row, col, text) so those
claims become assertions.
"""
import sys

sys.path.insert(0, '/root/projects/adaptix')

from src.adaptix.ui import screen as S
from src.adaptix.ui.state import LiveView, read_tokens

WIDTH, HEIGHT = 100, 30


class FakeWin:
    def __init__(self, height=HEIGHT, width=WIDTH):
        self.height, self.width = height, width
        self.cells = {}

    def getmaxyx(self):
        return self.height, self.width

    def erase(self):
        self.cells = {}

    def refresh(self):
        pass

    def addstr(self, y, x, text, attr=0):
        if y >= self.height or x >= self.width:
            raise RuntimeError(f'wrote outside the screen at {y},{x}')
        self.cells[(y, x)] = text

    def row_text(self, y):
        return ''.join(text for (row, _col), text in sorted(self.cells.items()) if row == y)


def _view():
    view = LiveView(model='autoapp/minimax-m3', target=['http://127.0.0.1:3000'],
                    run_id='ui-preview', status='running', iteration=3, max_iterations=40)
    view.tokens = read_tokens({'token_budget': 5_000_000, 'token_ledger': [
        {'provider_call': True, 'source': 'provider', 'tokens_charged': 20112,
         'prompt_tokens': 20112, 'completion_tokens': 940, 'model': 'autoapp/minimax-m3'}]})
    view.findings = [{'finding_type': 'sql_injection', 'severity': 'high',
                      'target': 'http://h/search?q=a'}]
    view.append('recon: 74 routes discovered')
    return view


class FakeCurses:
    A_BOLD = A_DIM = A_NORMAL = 0
    COLOR_CYAN = COLOR_GREEN = COLOR_YELLOW = 1
    error = RuntimeError

    @staticmethod
    def color_pair(value):
        return 0


class _Runner:
    running = True


def _draw(width=WIDTH, height=HEIGHT, view=None):
    original = S.curses
    S.curses = FakeCurses
    try:
        win = FakeWin(height, width)
        prompt_y, prompt_x = S.draw(win, view or _view(), _Runner(), 0)
        return win, prompt_y
    finally:
        S.curses = original


def test_the_prompt_is_the_bottom_of_the_screen():
    win, prompt_y = _draw()
    assert 'adaptix>' in win.row_text(prompt_y), win.row_text(prompt_y)
    # Panel is meter(2) + separator + prompt + help; the prompt is the second-last line.
    assert prompt_y == HEIGHT - 2, prompt_y


def test_the_token_meter_sits_directly_above_the_prompt():
    win, prompt_y = _draw()
    meter = win.row_text(prompt_y - 2)
    assert 'tokens' in meter, meter
    # The line reports tokens used, not a per-call breakdown: the operator asked for the
    # spent figure, and failed calls carry no prompt/completion split to print.
    assert 'used' in meter, meter
    assert 'calls' not in meter and 'failed' not in meter, meter


def test_no_token_number_is_cut_in_half_on_a_narrow_terminal():
    win, prompt_y = _draw(width=64)
    meter = win.row_text(prompt_y - 2)
    assert 'used' in meter, meter
    # Whatever survives must be a complete figure: no field may end mid-number.
    assert not meter.rstrip().endswith((',', ' /')), meter
    for token in meter.split():
        # A figure may be wrapped in parentheses ("(in 600"); the number itself is what
        # must be whole. Strip the punctuation the layout adds, then require digits only.
        figure = token.strip('()%/,')
        if figure and figure[0].isdigit():
            assert figure.replace(',', '').isdigit(), token


def test_layout_survives_a_short_terminal():
    win, prompt_y = _draw(height=16)
    assert 'adaptix>' in win.row_text(prompt_y)
    assert 'tokens' in win.row_text(prompt_y - 2)


def test_provider_list_noise_and_ansi_are_removed_from_the_log():
    line = '\x1b[1;31mProvider List: https://docs.litellm.ai/docs/providers\x1b[0m'
    assert S.clean_log_line(line) == ''
    assert S.clean_log_line('\x1b[31mreal progress\x1b[0m') == 'real progress'


def test_model_display_uses_the_cli_environment_name(monkeypatch):
    monkeypatch.setenv('ADAPTIX_LLM_MODEL', 'openai/autoapp/glm-5.3')
    monkeypatch.setenv('ADAPTIX_MODEL', 'wrong/model')
    assert S.configured_model() == 'openai/autoapp/glm-5.3'


def test_missing_model_explanation_does_not_render_a_fake_cause():
    view = _view()
    view.details = [{'severity': 'high', 'class': 'sql_injection', 'cwe': 'CWE-89',
                     'extracted': [], 'endpoint': 'http://h/search',
                     'url': 'http://h/search?q=1', 'payload': "1'",
                     'cause': '', 'mitigation': ''}]
    win, _prompt_y = _draw()
    rendered = '\n'.join(win.row_text(row) for row in range(HEIGHT))
    assert 'Penyebab belum dicatat' not in rendered
    assert 'Tinjau bukti pada laporan' not in rendered
    assert 'sebab' not in rendered
    assert 'perbaikan' not in rendered


def test_finding_header_uses_a_readable_title_and_never_a_question_mark():
    view = _view()
    view.details = [{'severity': '', 'class': '', 'title': 'temuan belum diklasifikasi',
                     'status': '', 'cwe': '', 'extracted': [],
                     'endpoint': 'http://h/search', 'url': 'http://h/search',
                     'payload': '', 'cause': '', 'mitigation': ''}]
    win, _prompt_y = _draw(view=view)
    rendered = '\n'.join(win.row_text(row) for row in range(HEIGHT))
    assert 'unrated' in rendered
    assert 'temuan belum diklasifikasi' in rendered
    assert '?' not in rendered


def test_scanner_match_is_labelled_apart_from_verified_findings():
    view = _view()
    view.details = [
        {'severity': 'medium', 'class': 'potential_vulnerability',
         'title': 'Indikasi scanner', 'status': 'scanner_matched', 'cwe': '',
         'extracted': [], 'endpoint': 'http://h/metrics',
         'url': 'http://h/metrics', 'payload': '', 'cause': '', 'mitigation': ''},
        {'severity': 'high', 'class': 'sql_injection', 'title': 'SQL injection',
         'status': 'verified', 'cwe': 'CWE-89', 'extracted': [],
         'endpoint': 'http://h/search', 'url': 'http://h/search',
         'payload': '', 'cause': '', 'mitigation': ''}]
    win, _prompt_y = _draw(view=view)
    rendered = '\n'.join(win.row_text(row) for row in range(HEIGHT))
    assert 'findings 2  (1 scanner match, 1 verified)' in rendered
    assert '[scanner match, belum diverifikasi]' in rendered


def test_runner_reads_progress_and_final_report_artifacts(tmp_path):
    import json
    from pathlib import Path

    base = Path(tmp_path) / 'artifacts' / 'scans' / 'r1'
    base.mkdir(parents=True)
    (base / 'progress-test.json').write_text(json.dumps({
        'node': 'final_report', 'phase': 'running', 'status': 'scope_ok',
        'stop_reason': None, 'iteration': 2}))
    (base / 'report-test.json').write_text(json.dumps({
        'status': 'completed_partial', 'stop_reason': 'no_new_actions',
        'llm_model': 'openai/autoapp/glm-5.3',
        'findings': [{'evidence_id': 'EV-1', 'finding_type': 'sql_injection',
                      'severity': 'high', 'target': 'http://h/search?q=a',
                      'parameter': 'q'}],
        'finding_explanations': {'EV-1': {'title': 'SQL injection',
                                           'cause': 'Model cause',
                                           'impact': 'Model impact',
                                           'remediation': 'Model remedy'}},
        'narrative': {'title': 'Model report', 'executive_summary': 'Summary'},
        'token_ledger': [], 'budget_status': {'token_budget': {'configured': 50000}},
    }))
    runner = S.Runner(LiveView())
    runner.run_id = 'r1'
    view = runner.poll_artifacts(str(tmp_path))
    assert view.status == 'completed_partial'
    assert view.model == 'openai/autoapp/glm-5.3'
    assert view.details[0]['cause'] == 'Model cause'
    assert view.narrative['executive_summary'] == 'Summary'
    assert view.workflow_node == 'final_report'

def test_token_budget_accepts_a_finite_limit_or_unlimited():
    assert S.parse_screen_budget('tokens=50000') == ('tokens', 50000)
    assert S.parse_screen_budget('tokens=unlimited') == ('tokens', None)
    try:
        S.parse_screen_budget('tokens=0')
    except ValueError:
        pass
    else:
        raise AssertionError('zero must not be accepted as a budget')

def test_tui_environment_budget_accepts_unlimited(monkeypatch):
    monkeypatch.setenv('ADAPTIX_TOKEN_BUDGET', 'unlimited')
    assert S.env_budget('ADAPTIX_TOKEN_BUDGET', 5000000) is None
    monkeypatch.setenv('ADAPTIX_TOKEN_BUDGET', '25000')
    assert S.env_budget('ADAPTIX_TOKEN_BUDGET', 5000000) == 25000

def test_runner_forwards_unlimited_tokens_and_the_remote_confirmation(monkeypatch):
    monkeypatch.setattr(S.Runner, 'interpreter', staticmethod(lambda: 'python'))
    unlimited = LiveView(target=['http://h'], token_budget=None)
    argv = S.Runner(unlimited).command('assess')
    index = argv.index('--token-budget')
    assert argv[index + 1] == 'unlimited'
    assert '--confirm-unlimited-remote' in argv

    finite = LiveView(target=['http://h'], token_budget=50000)
    argv = S.Runner(finite).command('assess')
    index = argv.index('--token-budget')
    assert argv[index + 1] == '50000'
    assert '--confirm-unlimited-remote' not in argv
