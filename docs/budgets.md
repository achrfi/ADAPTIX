# Execution budgets

Every execution budget accepts a positive integer **or the literal word `unlimited`**.
Internally `unlimited` becomes `None`: no cap applies, consumers never invent a
substitute number, and usage stays metered exactly as for finite budgets.

## CLI

```
--token-budget {(int|unlimited)}        default 50000
--time-budget  {(int|unlimited)}        default 1800 seconds
--tool-call-budget {(int|unlimited)}    default 20
--max-iterations {(int|unlimited)}      default 20
```

```bash
# unlimited everything, local provider (no remote risk)
.venv/bin/python -m src.adaptix.main --target http://127.0.0.1:3000 \
  --token-budget unlimited --time-budget unlimited \
  --tool-call-budget unlimited --max-iterations unlimited \
  --run-id my-run

# mixed: unlimited tool calls but a finite token spend
.venv/bin/python -m src.adaptix.main --target http://127.0.0.1:3000 \
  --tool-call-budget unlimited --token-budget 20000
```

Absent flags keep the historical finite defaults, so existing commands behave
identically to before this change.

## Remote-provider guard

Unlimited budgets on a paid or remote provider could spend without bound. When
the configured provider is not the local Ollama loopback (`unlimited_remote_risk`
in `src/adaptix/workflow/budget.py`: any `llm_api_key` or a non-loopback
`llm_api_base`), the CLI refuses to start until `--confirm-unlimited-remote` is
passed explicitly. The report mirrors this with `remote_unlimited_risk_confirmed`
in the run configuration audit.

## Engine transport cap

LangGraph requires an integer recursion limit, so unlimited runs use
`ENGINE_RECURSION_LIMIT = 2_147_483_000` (`src/adaptix/main.py`). This is the
graph engine's transport ceiling only — not a budget; the real bounds are the
configured budgets and the loop safeguards below.

## Stop reasons

Reports name the exact limiting cause instead of a generic exhaustion:

| Stop reason              | Meaning |
|--------------------------|---------|
| `token_budget_exhausted` | cumulative token spend reached the cap |
| `time_budget_exhausted`  | run wall-clock deadline reached (or too close for another provider call) |
| `tool_call_budget_exhausted` | cumulative tool calls reached the cap |
| `iteration_budget_exhausted` | planner passes reached `max_iterations` |
| `context_window_exceeded` | even full compaction cannot fit the provider context |
| `planning_stagnation`    | `consecutive_no_gain_passes` reached `no_gain_stop_limit` |
| `objective_completed`    | objective achieved per evidence, no further work stored |
| `operator_cancelled`     | SIGINT/SIGTERM; a partial report with everything metered so far is still written |
| `provider_error`         | the model provider failed (after bounded retries) |

Legacy `budget_exhausted` states are mapped through `budget_stop_reason` so
older runs still resolve to a specific cause. All same-family stops keep the
report status `stopped` (objective `completed_partial` unless achieved), except
`objective_completed`, which reports `completed`/`achieved`.

## Stagnation guard

Unlimited budgets make silent loops the main risk. The planner tracks
`consecutive_no_gain_passes` from each executed action's `goal_progress`; when a
run under an LLM planner records `no_gain_stop_limit` consecutive passes (default
4, configured floor 2) without answering a goal question, it stops with the
honest cause `planning_stagnation`. Finite-budget runs share the guard.

## Memory bound (not a budget)

`STORE_CACHE_BOUND = 512` (`src/adaptix/workflow/budget.py`) caps in-memory
decision/thinking-block cache entries. This is a memory-safety bound, not an
execution budget, and is never reported as budget usage.

## Retained hardcodes (documented, not removed)

- `src/adaptix/security/web_signatures.py` — payload and detection tokens. These
  are verification contracts (what a known class looks like), not test logic.
- `src/adaptix/agents/hypotheses.py` — OWASP category normalization; a taxonomy
  mapping, not a decision.
- `src/adaptix/agents/planner.py` (`OUTPUT_ENVELOPES`, `PLANNER_OUTPUT_TOKENS`)
  — provider-output transport limits with bounded retry rungs; independent of
  execution budgets.
- Deterministic recovery tier (`recovery_limit`, default 3) — a loop-avoidance
  fallback that redirects fully infeasible decisions; it never authors payloads
  and stays capped even with unlimited budgets.
- scanner minimum floors (e.g. nuclei seconds floor) — tool-transport minimums.
