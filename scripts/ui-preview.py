"""Render the real screen with a fake window, using the measured run's state."""
import glob
import json
import sys

sys.path.insert(0, '/root/projects/adaptix')

import curses
# color_pair needs an initialized curses screen; the fake window does the drawing.
if not getattr(curses, '_adaptix_stub', False):
    curses.color_pair = lambda _n: 0
    curses._adaptix_stub = True
from src.adaptix.ui.screen import draw
from src.adaptix.ui.state import read_tokens, view_from_state

RUN = '/root/projects/adaptix/artifacts/scans/js-long-114926'


class FakeWin:
    def __init__(self, height=30, width=100):
        self.height, self.width = height, width
        self.rows = {}

    def getmaxyx(self):
        return self.height, self.width

    def addstr(self, y, x, text, attr=0):
        line = self.rows.get(y, [' '] * self.width)
        for offset, char in enumerate(str(text)):
            if x + offset < self.width:
                line[x + offset] = char
        self.rows[y] = line

    def erase(self):
        self.rows = {}

    def refresh(self):
        pass

    def row_text(self, y):
        return ''.join(self.rows.get(y, [])).rstrip()


class NoopRunner:
    running = False
    run_id = 'js-long-114926'


state = json.load(open(sorted(glob.glob(RUN + '/checkpoint*.json'))[-1]))
view = view_from_state(state)
view.status = 'completed_partial'
view.elapsed = 3721.0

for height, width in ((30, 100),):
    win = FakeWin(height, width)
    draw(win, view, NoopRunner(), 0)
    print('=' * width)
    for y in range(height):
        text = win.row_text(y)
        if text.strip():
            print(f'{y:2d} | {text}')
    print('=' * width)
