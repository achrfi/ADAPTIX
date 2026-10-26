"""ADAPTIX terminal screen: type `adaptix`, get a prompt, watch a live token meter.

Design constraints that decided the shape of this file:

* No third-party UI dependency. Only ``rich``/``prompt_toolkit``/``textual`` were
  candidates and none is installed, so the screen is plain ``curses``.
* One execution path. The run is delegated to ``src.adaptix.main.main()`` with the same
  argv a CLI operator would type, so the TUI cannot drift from the CLI. The run happens
  in a worker thread and the screen reads its artifacts, because LangGraph's stream is
  a generator owned by that thread.
* Deterministic numbers. Tokens come from ``token_ledger`` (provider-reported prompt and
  completion counts), never from a guess or a local tokenizer.
"""
from __future__ import annotations

import curses
import glob
import json
import os
import re
import subprocess
import sys
import threading
import time

from src.adaptix.ui.state import (LiveView, read_tokens, view_from_progress,
                                  view_from_report, view_from_state)
from src.adaptix.workflow.budget import UNLIMITED_WORD, parse_budget

BANNER = [
    '    _   ___   _    ___ _____ _____  __',
    '   /_\\ |   \\ /_\\  | _ \\_   _|_ _\\ \\/ /',
    '  / _ \\| |) / _ \\ |  _/ | |  | | >  < ',
    ' /_/ \\_\\___/_/ \\_\\|_|   |_| |___/_/\\_\\',
]

HELP = (
    'Enter run · Ctrl-C during a run cancels it · /target URL · /model ID · '
    '/budget tokens=N|unlimited · /identity FILE · /clear · /help · /quit'
)

_ANSI = re.compile(r'\x1b\[[0-9;?]*[ -/]*[@-~]')
_PROVIDER_NOISE = ('Provider List:', 'LLM Provider NOT provided',
                   'Pass model as E.g.', 'Give Feedback', 'Get help')


def configured_model():
    return (os.getenv('ADAPTIX_LLM_MODEL') or os.getenv('ADAPTIX_MODEL')
            or os.getenv('OPENAI_MODEL') or '')


def clean_log_line(line):
    text = _ANSI.sub('', str(line or '')).rstrip()
    if not text or any(marker in text for marker in _PROVIDER_NOISE):
        return ''
    return text

def budget_argument(value) -> str:
    return UNLIMITED_WORD if value is None else str(value)

def env_budget(name, fallback):
    raw = os.getenv(name)
    if raw is None or not str(raw).strip():
        return fallback
    return parse_budget(str(raw).strip(), int)

def parse_screen_budget(argument):
    """Parse one /budget assignment; ``unlimited`` is None, never a fake number."""
    key, _, value = argument.partition('=')
    key, value = key.strip(), value.strip()
    if key not in ('time', 'tools', 'tokens', 'context'):
        raise ValueError('unknown budget')
    number = int(value) if key == 'context' else parse_budget(value, int)
    if number is not None and number < 1:
        raise ValueError('budget must be positive')
    return key, number

class Runner:
    """Owns one assessment run in a worker thread.

    The run is started as a subprocess of the same interpreter rather than a thread:
    ``main.main()`` installs signal handlers and calls ``argparse`` / ``SystemExit``,
    both of which are hostile inside the UI thread. A subprocess also means Ctrl-C in
    the UI cannot corrupt the run, and the artifacts it writes are the shared state.
    """

    def __init__(self, view: LiveView):
        self.view = view
        self.process: subprocess.Popen | None = None
        self.thread: threading.Thread | None = None
        self.run_id = ''
        self.lock = threading.Lock()
        self.finished = threading.Event()
        self.finished.set()

    @property
    def running(self) -> bool:
        return self.process is not None and self.process.poll() is None

    @staticmethod
    def interpreter() -> str:
        """The interpreter that has this project's dependencies.

        ``sys.executable`` is only correct when the screen was started by the venv
        python. Started as ``/usr/bin/python -m src.adaptix.ui_entry`` it points at the
        system interpreter, and every run then dies on a missing ``litellm``. Prefer the
        venv beside the project root, and prove it can import the stack before using it.
        """
        candidates = [sys.executable]
        for name in ('.venv/bin/python', 'venv/bin/python'):
            candidates.append(os.path.abspath(name))
        for candidate in candidates:
            if not candidate or not os.path.exists(candidate):
                continue
            try:
                probe = subprocess.run([candidate, '-c', 'import litellm, langgraph'],
                                       capture_output=True, timeout=60, cwd=os.getcwd())
            except (OSError, subprocess.SubprocessError):
                continue
            if probe.returncode == 0:
                return candidate
        return sys.executable

    def command(self, instruction: str) -> list[str]:
        view = self.view
        argv = [self.interpreter(), '-u', '-m', 'src.adaptix.main',
                '--instruction', instruction,
                '--run-id', self.run_id,
                '--model-context-tokens', str(view.context_tokens),
                '--time-budget', budget_argument(view.time_budget),
                '--tool-call-budget', budget_argument(view.tool_budget),
                '--token-budget', budget_argument(view.token_budget),
                '--max-iterations', str(view.max_iterations),
                '--planner-retries', '2',
                '--llm-timeout', '180']
        if any(value is None for value in (view.time_budget, view.tool_budget, view.token_budget)):
            argv.append('--confirm-unlimited-remote')
        for target in view.target:
            argv.extend(['--target', target])
        if view.identity:
            argv.extend(['--identity-context', view.identity])
        if view.model:
            argv.extend(['--model', view.model])
        extra = os.getenv('ADAPTIX_TUI_ARGS')
        if extra:
            import shlex
            argv.extend(shlex.split(extra))
        return argv

    def start(self, instruction: str, cwd: str):
        self.run_id = time.strftime('ui-%H%M%S')
        self.view.run_id = self.run_id
        self.view.objective = instruction
        self.view.status = 'starting'
        self.view.stop_reason = ''
        self.view.log = []
        self.view.started_at = time.time()
        self.view.append(f'objective: {instruction[:160]}')
        argv = self.command(instruction)
        self.view.append('exec: ' + ' '.join(argv[:6]) + ' ...')
        self.finished.clear()

        def work():
            env = dict(os.environ, PYTHONUNBUFFERED='1', COLUMNS='100')
            try:
                # The run's own output is captured, not discarded: a failure to start
                # (bad flag, missing credential, import error) otherwise leaves the
                # screen showing "run started" forever with no explanation.
                self.process = subprocess.Popen(argv, cwd=cwd, env=env,
                                                stdout=subprocess.PIPE,
                                                stderr=subprocess.STDOUT,
                                                text=True, bufsize=1)
                for line in self.process.stdout or []:
                    line = clean_log_line(line)
                    if (not line or line.startswith(('{', '}', '  ', '[EVENT]'))
                            or line.startswith('===') or line in ('[', ']')):
                        continue          # the final JSON dump is not progress
                    self.view.append(line[:400])
                code = self.process.wait()
                self.view.append(f'run finished (exit {code})')
                self.poll_artifacts(cwd)
            except OSError as exc:
                self.view.append(f'could not start the run: {exc}')
            finally:
                self.finished.set()

        self.thread = threading.Thread(target=work, daemon=True)
        self.thread.start()

    def cancel(self):
        if self.running:
            self.process.terminate()
            self.view.append('cancel requested')

    @staticmethod
    def _latest_json(base, pattern):
        paths = sorted(glob.glob(os.path.join(base, pattern)), key=os.path.getmtime)
        for path in reversed(paths):
            try:
                with open(path, encoding='utf-8') as handle:
                    value = json.load(handle)
            except (OSError, ValueError):
                continue
            if isinstance(value, dict):
                return value
        return None

    def poll_artifacts(self, cwd: str):
        """Read the newest LangGraph progress, checkpoint and report into the view."""
        if not self.run_id:
            return
        base = os.path.join(cwd, 'artifacts', 'scans', self.run_id)
        progress = self._latest_json(base, 'progress-*.json')
        if progress:
            self.view = view_from_progress(progress, self.view)
        checkpoints = sorted(glob.glob(os.path.join(base, 'checkpoint-*.json')))
        merged = None
        if checkpoints:
            try:
                with open(checkpoints[-1], encoding='utf-8') as handle:
                    state = json.load(handle)
            except (OSError, ValueError):
                state = None
            if state:
                merged = view_from_state(state, self.view)
                merged.tokens = read_tokens(state)
                if not progress:
                    phases = [row for row in (state.get('phase_runtime') or []) if isinstance(row, dict)]
                    if phases:
                        merged.workflow_node = str(phases[-1].get('phase') or '')
                        merged.workflow_phase = 'completed'
                    if self.running:
                        merged.status = 'running'
        report = self._latest_json(base, 'report-*.json')
        if report:
            merged = view_from_report(report, merged or self.view)
        if merged is None:
            merged = self.view
            if self.running:
                merged.status = 'running' if progress else 'starting'
        if not self.running and merged.status in ('starting', 'recon', 'running'):
            merged.status = 'finishing'
        if self.view.started_at:
            merged.elapsed = time.time() - self.view.started_at
        self.view = merged
        return merged


def _safe_addstr(win, y, x, text, attr=0):
    """curses raises when writing past the last column or line; clip instead."""
    height, width = win.getmaxyx()
    if y < 0 or y >= height or x >= width:
        return
    try:
        win.addstr(y, x, text[:max(0, width - x - 1)], attr)
    except curses.error:
        pass


def draw(stdscr, view: LiveView, runner: Runner, scroll: int):
    stdscr.erase()
    height, width = stdscr.getmaxyx()

    # Header: banner on tall screens, facts always.
    row = 0
    if height >= 26:
        for line in BANNER:
            _safe_addstr(stdscr, row, 1, line[:width - 2], curses.A_BOLD | curses.color_pair(1))
            row += 1
        row += 1
    for line in view.header_lines():
        _safe_addstr(stdscr, row, 1, line, curses.A_BOLD)
        row += 1
    if view.objective:
        _safe_addstr(stdscr, row, 1, 'goal    ' + view.objective[:width - 10], curses.A_DIM)
        row += 1
    _safe_addstr(stdscr, row, 1, '-' * max(1, width - 2), curses.A_DIM)
    row += 1

    # Tokens used, directly above the prompt so the number never scrolls away. There is
    # no usage bar: an operator reads a spent figure, not a percentage of a budget they
    # did not set.
    meter_lines = ['tokens  ' + view.tokens.summary(width)]
    panel_height = len(meter_lines) + 3          # meter + separator + prompt + help
    log_bottom = max(row, height - panel_height - 1)

    details = view.details or []
    if details:
        states = {}
        for detail in details:
            state = str(detail.get('status') or 'unrated')
            states[state] = states.get(state, 0) + 1
        labels = {'verified': 'verified', 'scanner_matched': 'scanner match',
                  'inconclusive': 'inconclusive', 'rejected': 'rejected', 'unrated': 'unrated'}
        breakdown = ', '.join(f'{count} {labels.get(name, name.replace("_", " "))}'
                              for name, count in states.items())
        heading = f'findings {len(details)}'
        if any(name != 'verified' for name in states):
            heading += f'  ({breakdown})'
        _safe_addstr(stdscr, row, 1, heading, curses.A_BOLD | curses.color_pair(2))
        row += 1
        shown = 0
        for detail in details:
            if row >= log_bottom:
                break
            status = str(detail.get('status') or '')
            badge = ''
            if status == 'scanner_matched':
                badge = '  [scanner match, belum diverifikasi]'
            elif status and status != 'verified':
                badge = '  [' + status.replace('_', ' ') + ']'
            title = detail.get('title') or detail.get('class') or 'temuan belum diklasifikasi'
            header = (f"{detail['severity'] or 'unrated'}  {title}{badge}"
                      + (f"  [{detail['cwe']}]" if detail.get('cwe') else '')
                      + (f"  extracted: {', '.join(detail['extracted'][:3])}" if detail.get('extracted') else ''))
            block = [(header, curses.A_BOLD | curses.color_pair(2)),
                     ('endpoint ' + detail['endpoint'], curses.color_pair(1)),
                     ('url     ' + detail['url'], curses.A_DIM)]
            if detail.get('payload'):
                block.append(('payload ' + detail['payload'], curses.A_DIM))
            if detail.get('cause'):
                block.append(('sebab   ' + detail['cause'], curses.A_NORMAL))
            if detail.get('mitigation'):
                block.append(('perbaikan ' + detail['mitigation'], curses.A_NORMAL))
            for text, attr in block:
                if row >= log_bottom:
                    break
                _safe_addstr(stdscr, row, 3, text[:width - 6], attr)
                row += 1
            shown += 1
        if len(details) > shown and row < log_bottom:
            _safe_addstr(stdscr, row, 3, f'... {len(details) - shown} lainnya di laporan',
                         curses.A_DIM)
            row += 1

    # Log tail: fill the remaining space, newest last.
    available = max(0, log_bottom - row)
    tail = view.log[-available - scroll:] if available else []
    if scroll:
        tail = tail[:max(0, len(tail) - scroll)] if scroll < len(tail) else []
    for line in tail[-available:] if available else []:
        _safe_addstr(stdscr, row, 1, line[:width - 3], curses.A_NORMAL)
        row += 1

    # Bottom panel.
    base = max(0, height - panel_height)
    for index, line in enumerate(meter_lines):
        attr = curses.A_BOLD | curses.color_pair(3)
        _safe_addstr(stdscr, base + index, 1, line[:width - 3], attr)
    _safe_addstr(stdscr, base + len(meter_lines), 1, '-' * max(1, width - 2), curses.A_DIM)
    prompt = 'adaptix> '
    _safe_addstr(stdscr, base + len(meter_lines) + 1, 1, prompt, curses.A_BOLD)
    _safe_addstr(stdscr, base + len(meter_lines) + 2, 1, HELP[:width - 3], curses.A_DIM)
    stdscr.refresh()
    return base + len(meter_lines) + 1, len(prompt)


TICK = object()          # "no key yet, let the caller poll and redraw"


def _readline(stdscr, y, x, initial: str = ''):
    """Read one line, yielding an idle tick instead of blocking.

    Returns ``(TICK, buffer)`` when no key arrived within the poll window. The caller
    must redraw and call again with that buffer: without the tick the outer loop never
    runs while a prompt is idle, so a live run would leave the screen frozen at
    "run started" with a token meter stuck at zero.
    """
    buffer = list(initial)
    curses.curs_set(1)
    height, width = stdscr.getmaxyx()
    _safe_addstr(stdscr, y, x, ' ' * max(0, width - x - 1))
    _safe_addstr(stdscr, y, x, ''.join(buffer)[-(width - x - 2):], curses.A_BOLD)
    stdscr.move(y, min(width - 2, x + len(buffer)))
    stdscr.refresh()
    deadline = time.time() + 0.4
    while time.time() < deadline:
        try:
            key = stdscr.get_wch()
        except curses.error:
            time.sleep(0.03)
            continue
        if key in ('\n', '\r'):
            curses.curs_set(0)
            return ''.join(buffer), ''.join(buffer)
        if key == '\x1b':
            curses.curs_set(0)
            return None, ''.join(buffer)
        if key in ('\x7f', '\b', curses.KEY_BACKSPACE):
            if buffer:
                buffer.pop()
        elif key == '\x15':                    # Ctrl-U clears the line
            buffer.clear()
        elif isinstance(key, str) and key.isprintable():
            buffer.append(key)
        deadline = time.time() + 0.4
    curses.curs_set(1)
    return TICK, ''.join(buffer)


def _run_screen(stdscr, cwd: str):
    curses.start_color()
    curses.use_default_colors()
    curses.init_pair(1, curses.COLOR_CYAN, -1)
    curses.init_pair(2, curses.COLOR_GREEN, -1)
    curses.init_pair(3, curses.COLOR_YELLOW, -1)
    curses.curs_set(0)
    stdscr.nodelay(True)
    stdscr.keypad(True)

    view = LiveView()
    from src.adaptix.config import load_dotenv, ROOT
    load_dotenv()
    view.model = configured_model()
    view.target = [os.getenv('ADAPTIX_TUI_TARGET')] if os.getenv('ADAPTIX_TUI_TARGET') else []
    view.identity = os.getenv('ADAPTIX_TUI_IDENTITY') or ''
    view.context_tokens = int(os.getenv('ADAPTIX_MODEL_CONTEXT_TOKENS') or 32768)
    view.time_budget = env_budget('ADAPTIX_TIME_BUDGET', 2400)
    view.tool_budget = env_budget('ADAPTIX_TOOL_CALL_BUDGET', 90)
    view.token_budget = env_budget('ADAPTIX_TOKEN_BUDGET', 5000000)
    view.max_iterations = int(os.getenv('ADAPTIX_MAX_ITERATIONS') or 40)
    view.append('adaptix ui ready. Type an objective and press Enter.')
    view.append('Set a lab target when it differs from .env, e.g. /target http://127.0.0.1:3000')
    runner = Runner(view)
    scroll = 0
    last_poll = 0.0
    pending = ''

    while True:
        view = runner.view
        # Fold fresh artifacts in while a run is live.
        if runner.running and time.time() - last_poll > 1.5:
            last_poll = time.time()
            updated = runner.poll_artifacts(cwd)
            if updated is not None:
                view = updated
        py, px = draw(stdscr, view, runner, scroll)
        typed, pending = _readline(stdscr, py, px, pending)
        if typed is TICK:
            if runner.running and time.time() - last_poll > 1.2:
                last_poll = time.time()
                updated = runner.poll_artifacts(cwd)
                if updated is not None:
                    view = updated
            continue
        pending = ''
        if typed is None:
            continue
        line = typed.strip()
        if not line:
            continue
        if line.startswith('/'):
            command, _, argument = line.partition(' ')
            argument = argument.strip()
            if command in ('/quit', '/exit'):
                runner.cancel()
                return
            if command == '/help':
                view.append(HELP)
            elif command == '/clear':
                view.log = []
            elif command == '/target':
                view.target = [argument] if argument else []
                view.append(f'target set to {view.target or "(none)"}')
            elif command == '/model':
                view.model = argument or configured_model()
                view.append(f'model set to {view.model or "(from .env)"}')
            elif command == '/identity':
                view.identity = argument
                view.append(f'identity file set to {argument or "(none)"}')
            elif command == '/budget':
                if not argument:
                    view.append(
                        f'budget time={budget_argument(view.time_budget)} '
                        f'tools={budget_argument(view.tool_budget)} '
                        f'tokens={budget_argument(view.token_budget)} '
                        f'context={view.context_tokens}')
                    continue
                try:
                    key, number = parse_screen_budget(argument)
                    if key == 'time':
                        view.time_budget = number
                    elif key == 'tools':
                        view.tool_budget = number
                    elif key == 'tokens':
                        view.token_budget = number
                    elif key == 'context':
                        view.context_tokens = number
                    view.append(f'budget {key} = {budget_argument(number)}')
                except ValueError:
                    view.append('usage: /budget [time=N|unlimited tools=N|unlimited '
                                'tokens=N|unlimited context=N]')
            else:
                view.append(f'unknown command {command}; /help for the list')
            continue
        if runner.running:
            view.append('a run is already active; Ctrl-C cancels it')
            continue
        if not view.target:
            env_target = os.getenv('ADAPTIX_TUI_TARGET')
            if env_target:
                view.target = [env_target]
        if not view.target:
            view.append('no target set — use /target http://host:port before starting a run')
            continue
        runner.start(line, cwd)
        view.append('run started — the token meter updates from the provider ledger')


def main(cwd: str | None = None) -> int:
    cwd = cwd or os.getcwd()
    if not sys.stdout.isatty():
        print('adaptix ui needs an interactive terminal (a real TTY).')
        return 2
    os.environ.setdefault('ESCDELAY', '25')
    try:
        curses.wrapper(_run_screen, cwd)
    except KeyboardInterrupt:
        return 130
    return 0
