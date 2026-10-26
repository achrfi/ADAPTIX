# ADAPTIX terminal UI

Run `adaptix` with no arguments and the screen opens. Arguments are passed straight
through to the CLI, so `adaptix --help` still behaves like the CLI.

```
/root/projects/adaptix/.venv/bin/adaptix
```

## What the screen shows

Header — target, model, run id, status, pass counter, elapsed seconds. The model comes
from `ADAPTIX_LLM_MODEL` in `.env` (the same variable the CLI uses), and the status line
names the current LangGraph node and phase from the run's live `progress-*.json`.

Findings — one block per vulnerability, with only the recorded fields:

```
critical  sql_injection  [CWE-89]  extracted: password_hash
  endpoint  http://127.0.0.1:3000/rest/products/search
  url       http://127.0.0.1:3000/rest/products/search?q=%27%29%29
  payload   x')) UNION SELECT 1,2,3,4,5,6,7,8,9,password FROM Users WHERE password IS NOT NULL ORD
  sebab     Model: nilai q dirangkai ke query tanpa parameter binding, sehingga ...
  perbaikan Model: gunakan prepared statement untuk parameter q ...
```

- `endpoint` is the path without its query string; `url` is the request as it was sent.
- `payload` is the exact input the run used. When a record kept it only on its attempt
  rows, it is recovered from there rather than left blank.
- `sebab` and `perbaikan` are written by the report model from the recorded evidence.
  They appear after the final report exists; before that the lines are omitted rather
  than filled with a fixed fallback. Class titles and CWE labels stay local metadata.

The block height follows the available fields, so on a short terminal fewer findings are
drawn and the remainder is named (`... N lainnya di laporan`) rather than silently dropped.

Tokens — one line, directly above the prompt:

```
tokens  used 666,503  (in 624,915 / out 41,588)  of 9,000,000
```

This is the figure the provider charged. There is no usage bar and no per-call
breakdown: failed provider calls carry no prompt/completion split, and a field printed as
`out 0` on a run that had spent 666,503 tokens read as "nothing was spent". When the
budget was never set the `of N` part is omitted, and the prompt/completion split is shown
only when the provider reported it.

## Deduplication

The screen keys a finding on `(path, parameter, class)` and keeps the strongest record —
a proven-impact record wins outright, otherwise the higher severity wins. This is the same
rule the report uses, so the count on screen matches the count in the deliverable. Without
it the screen listed the extraction as `critical` and the boolean proof of the same hole
as `high`: two rows for one vulnerability.

## Commands

```
/target URL      /identity FILE      /model ID
/budget          # show current limits
/budget tokens=50000
/budget tokens=unlimited
/budget time=2400 tools=90 context=32768
/clear           /help               /quit
```

`tokens` accepts either a finite positive number or `unlimited`. Unlimited keeps
metering the spend but removes the cumulative token ceiling; provider context windows,
per-call timeouts and the other budgets still apply. The same choice can be set in
`.env` with `ADAPTIX_TOKEN_BUDGET=50000` or `ADAPTIX_TOKEN_BUDGET=unlimited`.

Enter starts a run with the typed line as the objective. Ctrl-C during a run cancels it.

## Tests

```
.venv/bin/python -m pytest tests/test_ui_state.py tests/test_ui_screen.py tests/test_ui_detail.py tests/test_workflow_progress.py -q
.venv/bin/python scripts/ui-preview.py     # render a frame without a terminal
```

`tests/test_ui_detail.py` runs against a real checkpoint, so it fails if the token line
ever prints a breakdown again, if a finding loses its endpoint/payload, or if one hole
starts appearing twice.
