# Day 3 — Honest budgets and `/resume` in the UI

Two operator-facing gaps closed. Both were found by using the product, not by
reading it.

## 1. A resumed run reported the wrong spend

**Symptom.** A run stopped at its tool-call limit was resumed with a larger limit.
Its report then claimed more calls used than the limit allowed:

```
before:  {'configured': 20, 'used': 42, 'remaining': 0}
after:   {'configured': 25, 'used': 31, 'remaining': 0}
```

`used > configured` is not a cosmetic error. It tells an operator the run obeyed a
budget it did not obey, or that it blew a budget it stayed within. Either reading is
wrong, and a security report that misstates its own spend cannot be trusted about
anything else.

**Why it happened.** Two defects, in sequence.

1. `execution_metrics.tool_calls_used` is cumulative from the first run. A resume
   replaces `tool_call_budget` with the new operator limit but kept the old
   counter, so the report measured the previous run's spend against this run's
   limit. Fixed by resetting the live counters on resume and archiving the earlier
   total under `execution_metrics.history`, so the record is complete rather than
   erased.

2. The reset was then silently undone. `run_stream` merges every streamed snapshot
   over the seed (`merged = {**merged, **update}`), and a snapshot is a *complete*
   state. LangGraph replays a thread's earlier snapshots before executing the next
   node, and those carry the previous process's totals -- so the replayed snapshot
   put the old counter back over the reset value. The live counter was correct
   (a trace showed `used=0` at the first check) while the report printed the
   replayed number. Fixed by refusing to let a replayed counter, which is lower than
   the seed's, overwrite it.

**Proof.** Real tool executions were counted independently and compared with what
the report claims:

| scenario | real calls | reported `used` | match |
|---|---|---|---|
| resume, budget 25, stopped at `max_iterations` | 9 | 9 | yes |
| resume, budget 25, ran to a planner stall | 4 | 4 | yes |
| resume, budget 25, many iterations | 12 | 12 | yes |

Before the fix the same runs reported 31, 33 and 39 against a limit of 25.

Note what this fix does *not* claim: a resumed run that keeps planning more tool
calls can legitimately spend more than the limit, because tools add to the counter
before the next budget check. That overshoot is real spend and is now reported as
such -- it is no longer confused with the bookkeeping error above.

**Tests.** `tests/test_resume_budget_accounting.py` (6 tests) locks the counter
reset, the history archive, and the guarded merge.

## 2. `/resume` inside the screen

Previously the only way to continue a UI-started run was to leave the screen and
reconstruct the CLI command by hand. The screen could not do it for two reasons: it
minted a fresh `ui-%H%M%S` id on every Enter, and it had no resume command.

```
/resume            list runs that still have work to do
/resume ID         continue that run on the next Enter
/resume last       continue the newest resumable run
/resume none       cancel a pending resume
```

Behaviour:

- A resume **keeps the id being continued**. Minting a new one is the bug that made
  an earlier attempt look like a resume while actually starting over: the
  checkpoint is looked up under the new id and not found.
- The intent is **one-shot**. It is consumed by the run it starts, so the next
  Enter is a new run instead of silently re-entering the same thread.
- A run that already finished is **not offered**. `resumable_runs()` mirrors what
  `--resume` itself accepts, so the screen never suggests a run the engine would
  refuse.
- Budgets set with `/budget` apply to the resumed portion, which is why the
  accounting fix above matters to this command.

**Tests.** `tests/test_ui_resume.py` (6 tests) locks the flag plumbing, the kept
id, the fresh-run id, and one-shot consumption.

## 4. A fresh run stopped in 32s because the port in the target was discarded

**Symptom.** A new session against `127.0.0.1:3000` reported:

```
Static Discovery: skipped, origin unreachable
Web Discover: 0 in-scope routes from 0 documents
Adaptive Planning (llm): 0 actions, 24328 accumulated tokens
status: completed_with_errors   stop_reason: no_new_actions   pass 3/40   32s
```

The target was serving throughout. The run was not blocked; it was aimed at the
wrong place.

**Root cause — two defects in one normalization.**

1. `_parse_target()` validated a port and then returned only the host:

   ```python
   parsed = urlsplit('//' + value)
   if parsed.port is not None and not 1 <= parsed.port <= 65535:
       raise ValueError('Port target di luar batas')
   return canonical_host(parsed.hostname)   # the port is gone
   ```

   `127.0.0.1:3000` became `127.0.0.1`. The planner then honestly planned
   `http://127.0.0.1` -- port **80**, where nothing was listening.

2. `scope_ports()` only read a port from a scheme URL (`'://' in value`), so a bare
   `host:port` contributed nothing and ports came from policy alone (default
   `80,443`). Port 3000 was never in scope even in principle.

**Fix.** The port named by the operator is authorization scope:

- `_parse_target()` preserves it (`127.0.0.1:3000` stays `127.0.0.1:3000`);
- `scope_ports()` adds it to policy ports rather than replacing them;
- `resolve_scope()` separated the host from its port before resolution, because
  preserving the port exposed a third defect: `127.0.0.1:3000` was passed to
  `ipaddress.ip_address()` and then to DNS, failing with
  `Gagal DNS untuk 127.0.0.1:3000`.

**Proof.** The reported command, re-run verbatim, fresh session:

```
before:  Web Discover: 0 in-scope routes from 0 documents
         limitations: [{'url': 'http://127.0.0.1', 'reason': 'origin_unreachable'}]

after:   74 in-scope routes from 3 documents
         limitations: NONE
         planner: "The only in-scope origin is 127.0.0.1:3000"
```

**Tests.** `tests/test_target_port_preserved.py` (17 tests) locks port preservation
through normalization, entry into scope, and host/port separation during resolution.

**A second round of defects, caught by the existing suite.** Preserving the port
meant every address form had to be distinguished from `host:port`. Three shapes are
NOT ports, and each was found by a failing test rather than by inspection:

| Input | What went wrong | Why |
|---|---|---|
| `2001:db8::10` | truncated to `2001` | `urlsplit('//2001:db8::10').hostname` is `'2001'` |
| `10.0.0.0/8` | mask dropped to one address | `urlsplit` reads the mask as a URL path |
| `2001:db8::/64` | `Port could not be cast... 'db8::'` | the parser reads colons as a port |

The rule: an address is recognized by `ipaddress` BEFORE any URL parsing, and only a
trailing single colon group after a non-bracketed host may be a port. All three
authorization tests that failed were correct to fail -- they were protecting a
regression, not asserting stale behaviour.

## 3. A resume no longer demands a target it already has

**Symptom.** Continuing a run meant retyping the target it had already stored. The
UI even warned "no target set" while arming a resume, then refused to start the run
it had just armed.

**Why.** `main.py` checked `--target` *before* any resume branch:

```python
if not args.target:
    parser.error('--target is required unless --check-tools is used')
```

The checkpoint stores the target (`['http://127.0.0.1:3000']`), so the flag was
asking for information the run already owned.

**The rule chosen.** The target is the authorization boundary, so it is never taken
silently:

- inherited **only** when the operator names none, and the accepted value is printed;
- an explicit `--target` always wins, because widening or narrowing scope is the
  operator's decision, not an artifact's;
- a resume with no checkpoint reports *that*, instead of demanding a flag that
  would not help.

**Proof.** From the screen, with no target typed anywhere:

```
target flags in argv: NONE
resume inh3: target inherited from its checkpoint (http://127.0.0.1:3000)
resuming run inh3: continuing at execute_action
```

**Tests.** `tests/test_resume_target_inheritance.py` (6 tests) locks the ordering of
the gate, the operator-wins guard, and the missing-checkpoint message.

## 5. A resumed run kept showing the status of the attempt before it

**Reported:** after `/resume` the UI stayed on the old run's status instead of the
status of the resumed run.

**Reproduced** with `artifacts/scans/rstest` and `norestart`: the resume itself was
correct (`resuming run norestart: continuing at state_update`, events growing
13 -> 18 -> 22), but the status line did not follow it.

Three presentation defects, all in the UI layer - the engine was never at fault:

1. `ui/screen.py` picked the newest checkpoint with `sorted()` (filename order).
   A resume rewrites `checkpoint-0001..N`, so name order can point at a snapshot
   from before the resume. Now sorted by `os.path.getmtime`.
2. `ui/screen.py` read `progress-*.json` unconditionally. That file is rewritten in
   place and still holds the previous attempt's last state (`final_report`,
   `completed`), so the resume appeared frozen on the old status. A progress file
   older than the run's own start time is now ignored (`_is_stale`).
3. `ui/state.py` let a resumed snapshot overwrite `run_id` and the pass counter.
   `run_id` is now only taken when the view has none, and the displayed pass comes
   from `execution_metrics.iterations_used` (which resume resets to 0) instead of
   the graph's `iterations` (which keeps counting from before the resume).

**What was deliberately not changed:** the resume path itself. `main.py`,
`evidence/checkpoint.py` and `workflow/graph.py` are untouched, so a resume still
continues from the last checkpoint and keeps the earlier work.

Evidence:

```
resuming run norestart: continuing at state_update
checkpoint events       13 -> 18 -> 22          (a restart would reset these)
stale progress file     node=final_report phase=completed   (now rejected)
UI pass displays        0/3                     (live counter, not graph 3)
UI run_id               norestart               (not hijacked)
```

Locked by `tests/test_resume_status_refresh.py` (13 tests).

## 6. Refused surfaces are not re-offered (run `ui-225618`, stop `no_feasible_action`)

### Symptom

Run `ui-225618` stopped with `no_feasible_action` after 23 of 40 passes. It had two
valid findings (critical SQL injection, medium XSS), 17 passes and seven untried
endpoints left. The stop reason is raised at `planner.py:1637` only once
`consecutive_infeasible_actions` reaches `infeasible_stop_limit` (default 6):

```
checkpoint-0018  consecutive_infeasible_actions = 1
checkpoint-0019  = 2
checkpoint-0020  = 3
checkpoint-0021  = 4
checkpoint-0022  = 5
checkpoint-0023  = 6   -> stop
```

### Root cause

Two separate defects, both in the presentation of policy feedback to the model:

1. **`_fixation` reset on every surface change.** The counter is single-slot: it
   returns `1` whenever the proposed surface differs from the previous pass. The
   model alternated between two refused surfaces, so the count never reached
   `_FIXATION_LIMIT = 2` and the escalation directive was never emitted. A
   multi-surface proposal cleared it outright (`len(keys) != 1 -> return None, 0`).
2. **Rejections re-advertised the refused surfaces as alternatives.** `_alternatives`
   built its list from the current pass only. Each rejection therefore suggested the
   same dead ends back to the model, which is the contradiction that makes a model
   repeat itself.

Measured refusal sequence from the real decision log:

```
pass 17  union_extract /rest/products/search?q=        -> already_completed
pass 18  union_extract /rest/products/search?q=        -> previously_rejected
pass 19  http_request  /rest/user/security-question    -> already_completed
pass 20  union_extract /rest/user/security-question    -> previously_rejected
pass 21  nuclei        /metrics                        -> already_completed
pass 22  http_request  /rest/user/security-question    -> previously_rejected
```

Seven executable endpoints (`/address/create`, `/address/edit/`, `/address/saved`,
`/address/select`, `/rest/user/change-password?current=`, `/2fa/enter`, `/api/Users`)
were listed as alternatives on every one of those passes and never attempted.

### Fix

- `_fixation` tracks the **union** of refused surfaces across passes. A refusal whose
  surface was refused earlier in the run is a continuation of the loop;
  only a surface never refused before restarts the count.
- `_refused_surfaces(state)` / `_is_refused(...)` read the whole refusal history
  (`refused_surfaces` plus `rejected_actions`), keyed by surface so a changed query
  value does not read as a new endpoint.
- The alternative list handed to the model excludes any refused surface. When the
  filtered list is empty, the directive keeps `code='choose_alternative'` (so the
  fixation escalation still fires) and states plainly that the suggestion list is
  empty rather than inviting the model to pick from nothing.
- `_as_surface_set` normalises every persisted shape (`endpoint_key` tuple, list,
  set, frozenset, legacy scalar) so a resumed checkpoint from before this change
  still reads correctly.
- `refused_surfaces: list` declared in the graph state schema; persisted in the
  planner state delta so it survives to the next pass and across a resume.

### Effect, replayed on the real pass sequence

```
pass 15: count=1
pass 16: clean pass (executed) -> count=0
pass 17: count=1
pass 18: count=2  escalation FIRES
pass 19: count=3
pass 20: count=4
pass 21: count=5
pass 22: count=6
```

Escalation now fires at pass 18 instead of the run dying at pass 23 - four passes
earlier, while budget and untried endpoints remain.

### Tests

`tests/test_refused_surfaces.py` (9) locks the counter across alternating surfaces,
the multi-surface accumulation, per-surface refusal matching, the exclusion of
refused surfaces from suggestions, every persisted key shape, and the state-delta
persistence.

### Honest scope

This changes which suggestions the model receives; it does not change the validator.
A refused action is still refused for exactly the same reasons. Whether the model
pivots is its own decision - the fix removes the contradiction, it cannot force a
better choice. Verified by replaying the recorded pass sequence, not by a new
end-to-end run against Juice Shop.

## 7. A fresh payload reopens a refused surface

### Why the previous fix was too broad

Section 6 stopped the planner from re-offering refused surfaces. That was right for
paths the run had closed, but the refusal identity is a **full request identity**
including the query string:

```
endpoint_key('http://127.0.0.1:3000/rest/products/search?q=1')
  -> ('http', '127.0.0.1', 3000, '/rest/products/search', 'q=1')
```

Condemning the whole surface therefore hid the single most useful pivot a scanner
has: the same endpoint with a **different payload**. Blind injection, filter bypass
and encoding work all depend on re-sending the same path with a new value.

### The rule now

| Situation | Suggestable? |
|---|---|
| same (path, value) refused before | no |
| same path, **different** value | **yes** |
| path already executed to completion | no (any value) |
| refused with no query parameter | no (path closed) |

A pair that returns under this rule carries
`requires_new_parameter_value: True`, and the directive says so explicitly:

> A pair marked requires_new_parameter_value is reachable only with a parameter
> value the run has not sent yet; re-sending the refused value is refused again.

The marker is advisory, not a gate. The model may still propose anything it can
justify; the validator decides, exactly as before.

### Implementation

`src/adaptix/agents/planner.py`

- `_value_bound_surfaces(state)` - surfaces whose refusal carried a query string.
- `_is_refused(..., allow_value_bound=False)` - default behaviour unchanged. With
  `allow_value_bound=True`, the comparison is **exact**: `seen[:4] == key[:4] and
  seen[4] == key[4]` refuses a repeated value; any other value returns `False`.
  Executed-to-completion surfaces return `True` before the value is considered,
  so no payload reopens them.
- The alternative filter passes `allow_value_bound=True` and tags reopened pairs.

### A bug caught while proving it

The first cut compared only `key[:4]`, so it could not tell "same value again" from
"new value" and allowed both. The exact comparison above fixed it; the table in
`tests/test_payload_reopens_surface.py` locks all four situations.

### Evidence

```
refused: ?q=1 (one value)
  same value ?q=1                    -> refused: True
  different payload ?q=' OR 1=1--    -> refused: False

same endpoint, already EXECUTED
  same value                         -> refused: True
  different payload                  -> refused: True

refused with NO query parameter (/metrics)
  suggestable                        -> True   (closed at path level)
```

Tests: `tests/test_refused_surfaces.py` (9) + `tests/test_payload_reopens_surface.py` (7).

### Boundary

No change to the evidence layer (`verification.py`, `coverage.py`), to the
validator, or to findings already stored. This section only widens what policy may
*suggest*; it never widens what the run may *conclude*.

## 8. Test behaviour instead of source text

Nine assertions across five test files read the planner's source with
`inspect.getsource` and searched the text, e.g.

```python
source = inspect.getsource(planner.adaptive_planning)
assert 'for fraction in (' in source
source.split('for fraction in (')[1].split(')')[0]
```

Those tests verified the *writing*, not the *work*. A behaviour-identical
refactor failed them; a broken function could pass them. They were also the
source of the flake seen twice on the full suite: `getsource` resolves through
the line table captured at import time, so for a short window after
`planner.py` was edited the returned fragment was wrong and eight tests failed
with `IndexError`. The mechanism was never reproduced on a settled file, but
the class of failure is structural, not incidental.

### What changed

Assertions now call the code and inspect the result:

| File | Before | After |
| --- | --- | --- |
| `test_recompaction.py` | grep for the fraction tuple and split it out of the source | call `compact_context(...)` and assert the returned token count is below the target, that the floor is reported, and that strict/permissive differ |
| `test_planner_knobs_reach_the_graph.py` | grep the whole module for two knob names | call `request_decision(...)` with an intercepting provider and assert the knobs arrive in the kwargs actually sent |
| `test_starvation_loop.py` | grep for `break` | call `request_decision(...)` with a permanently starved provider and assert the number of provider calls is bounded |
| `test_starvation_recovery.py` | grep for `allow_over_budget` and `max(0, context_window - retry_cost)` | call `compact_context(...)` and assert the retry envelope shrinks and the floor is honoured |
| `test_window_collision.py` | grep for the local rebinding of `window` | call `adaptive_planning(...)` and assert the returned `scope_window` is still the list of units |
| `test_adaptix_nuclei_assessment.py` | grep `main()` for a dict literal | AST check that the key exists in the module's string constants |
| `test_vuln_probes.py` | grep the probe for a returned key | AST check that the `return` statement actually carries the key |
| `test_union_capability.py` | grep for `list(... or [])` | call the coercion helper with `None` and `[]` |
| `test_planner_large_target.py` | grep the module for a rule sentence | AST check over the module's string constants |
| `test_adaptix_planning_recovery.py` | lowercase the whole source, comments included, and forbid eleven needles | AST check over emitted string constants only |

When a behaviour is not reachable without a live provider, the fallback is
`ast` parsing -- never `split()` on source and never a substring search over the
whole file, which a comment can satisfy and a reword can break.

### Notes

- No production file changed. This section is tests only.
- Remaining `getsource` calls feed `ast.parse`; they read program *structure*,
  not text, and are not sensitive to whitespace or line numbers.
- `test_vuln_probes` no longer forbids the string `authorization_findings` in a
  comment. Documenting a removed key is not a defect; returning it is.
