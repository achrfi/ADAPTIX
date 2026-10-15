# ADAPTIX Iterasi 6: adaptive loop refactor

## Architecture

Free user objective (`--instruction`) is independent of the dynamically selected scope (`--target`). Local CLI invocation attests authorization for the selected targets and automatically issues a one-hour signed grant with the worker-local key. `--authorized` is removed. Existing grants can still be supplied with `--grant`/`--principal` or `ADAPTIX_SCOPE_GRANT`/`ADAPTIX_PRINCIPAL`. The objective cannot expand scope.

One compiled LangGraph:
`scope_guard -> adaptive_planning -> execute_action -> observation_processing -> reflection_verification -> state_update -> adaptive_planning`.
An empty valid decision, model failure or exhausted budget exits to a report. Rejected planner actions return structured policy feedback through observation/reflection into the next bounded planning pass; they do not execute tools. Scope rejection exits before the model or scanners run.

The model must return a nonempty reflection and can propose competing next actions. Structured priority estimates relevance, information/evidence gain, confidence, marginal context tokens, seconds and requests. The controller ranks feasible candidates, executes only the highest score, and replans from actual observations/cost feedback. Candidate lists are alternatives, not an attack sequence. No initial mandatory Nmap, injected HTTPX dependency, tool ordering, terminal IDOR stage or offline scanner fallback remains. Fixed security constraints and capability implementations remain intentional.

Capabilities: Nmap (one pinned host), ProjectDiscovery HTTPX with technology detection, Nuclei with evidence-based HTTP template selection, browser observation, IDOR/BOLA comparison (one operator-configured scenario). Add adapters in `tool_handlers()` and registry metadata; graph topology stays unchanged. Adaptive Nuclei maps products from the selected host/port and HTTP technology observations to trusted tags; unknown products use native automatic detection. Configured full/default, baseline and local-template modes remain available. Template matches are unverified, and the supplied baseline measures reachability only. See `NMAP_NUCLEI_COVERAGE.md` for selection and budget behavior.

Observation/evidence triage remains deterministic: status/severity cannot confirm vulnerabilities. Browser observations include status, title, bounded page text and in-scope discovered links; HTTP observations include status/title/technology facts. Observed page text remains untrusted data. The next planner decision contains required model self-reflection; deterministic triage remains separate so model opinion cannot promote a finding. IDOR retains Iterasi 6 response comparison evidence and counts both identity requests before starting. Operator must supply distinct identities and known object ownership; identical public responses alone do not establish ownership.

Grant signature, principal, expiry, pinned hosts and policy are rechecked before execution. Ports and blocked address classes remain policy constraints. Fixed host and per-run URL count caps are removed; the full selected scope remains authoritative while a budget-sized window feeds the planner. Budgets cover planning passes, external tool calls, provider-reported model tokens and wall-clock seconds (`--time-budget`, default 1800). Default planning-pass budget follows `--tool-call-budget`; `--max-iterations` remains an explicit override. Tool timeouts are clamped to remaining time. Failed completion reserves prompt/output budget; unknown local tokenizer uses conservative UTF-8 byte reservation. Exact tokenizer accounting depends on provider usage. Tools keep bounded requests, redirects and evidence storage.

## Install and verify (Linux server)

```sh
cd /root/projects/adaptix
source /root/miniforge3/etc/profile.d/conda.sh
conda activate base
LITELLM_LOCAL_MODEL_COST_MAP=True python -m pytest -q
```

The project's runtime is Conda `base` at `/root/miniforge3` (Python 3.13.13). All 70 tests passed in this environment after staged scope and utility/cost priority changes. If dependencies need installation on another machine, use `python -m pip install -e '.[test]'` in its chosen environment. Keep `.env`, signing key, authorizations, artifacts and benchmarks private and unchanged. Existing `requirements.lock` predates this change; `pyproject.toml` is the dependency source for these commands. Regenerate the lock in your normal environment before adopting a locked deployment.

## Run

```sh
python -m src.adaptix.main --target https://your-domain.example \
  --instruction 'Tinjau kontrol akses API dan jelaskan bukti serta keterbatasannya' \
  --model ollama_chat/qwen3:14b --max-iterations 12 --tool-call-budget 20
```

CLI targets can be domain names, HTTP(S) URLs, IPv4, IPv6 or CIDRs; repeat `--target` for multiple entries. No static domain/IP allowlist needs editing. The CLI creates its signed grant automatically; `--grant` remains an optional override. Explicit URL ports are added to this run's ports alongside configured probe ports. CIDRs stay compressed as network declarations and are iterated lazily, including large IPv6 ranges. Selected seed URLs on the same host are distinct work units. The authority boundary remains the authorized hosts/CIDRs; additional discovered paths within those hosts are eligible. Dynamic domain aliases retain logical URLs in observations and reports, while HTTPX/Nuclei connect to pinned IPs with the original Host header/TLS SNI. Browser DNS is pinned through Chromium resolver rules; IDOR preserves hostname verification and identity headers over its pinned connection. `--idor-scenarios scenarios.json` loads a list of Iterasi 6 scenario objects (name, base_url, path_template, object_id, owner_identity, other_identity, method=GET). Credentials stay out of model context. No default user objective or attack sequence is supplied.

## Review and commit

```sh
git diff --check
git diff --stat
git diff -- .gitignore config/scope.yaml src tests pyproject.toml INTEGRATION.md ADAPTIVE_AUDIT.md
git add .gitignore config/scope.yaml src tests pyproject.toml INTEGRATION.md ADAPTIVE_AUDIT.md
git commit -m "Refactor Iterasi 6 into one adaptive LangGraph action loop"
```

Review staged paths before commit. `benchmarks/` is pre-existing untracked work and is excluded. No commit or GitHub push is performed automatically. The `.venv` created during the earlier verification is not the project's runtime. A pre-change server tar backup is stored under `/root/adaptix-backups/`; restore only reviewed paths if rollback is needed.

Regression tests include compact signed grant v2 (and legacy v1 verification), staged large-CIDR scope, more than 32 eligible URLs, distinct selected URL work units, priority ranking and cost feedback, signed grants, DNS pinning, scope boundaries, budgets, evidence triage, Iterasi 6 IDOR, no model fallback, direct browser-first execution, and observation/reflection feedback into replanning. The regression suite mocks scanner/model boundaries. Separate live Qwen3/Ollama runs exercise browser discovery of a runtime-generated link and an HTTP-only instruction against a temporary local lab; evidence is in `artifacts/live-audit/` and execution traces in `artifacts/runtime/`. This verifies adaptive planning examples, not general pentest coverage or research efficacy.

## LangGraph dev service

The current development service runs as root with Conda `base` on port 2024:

```sh
cd /root/projects/adaptix
source /root/miniforge3/etc/profile.d/conda.sh
conda activate base
LITELLM_LOCAL_MODEL_COST_MAP=True langgraph dev --host 0.0.0.0 --port 2024 --no-browser --no-reload --allow-blocking
```

API health: `http://172.31.154.203:2024/ok`; API docs: `http://172.31.154.203:2024/docs`. Graph ID: `adaptix`. For Studio/API input, use `user_prompt` as the free objective (the CLI name is `--instruction`), plus `target` and a valid grant/principal for non-loopback scope. The redundant `authorization_confirmed` field is no longer used. API callers cannot issue their own grants; use an operator grant or the grant saved by a local CLI run in `artifacts/authorizations/`. Process ID and service log are recorded in `artifacts/runtime/langgraph-dev.pid` and `.log`. The server runs without reload; restart it after code changes. It is a background development process, not an installed boot service.

## Dynamic scope validation

Offline regression covers domains outside any static allowlist, URL ports, IPv6/CIDRs, automatic CLI grants, unknown-domain rejection and DNS changes before execution. Live domain/TLS validation ran HTTPX, Nuclei, Playwright and IDOR against a temporary virtual-host lab, verified the original Host header and TLS SNI, then ran the CLI with Qwen3 without `--authorized`, `--grant` or `--principal`. The CLI selected HTTPX, returned HTTP 200, and stopped. Evidence: `artifacts/dynamic-scope-audit/summary.json`; trace: `artifacts/runtime/dynamic-scope-audit.log`. No public domain scan was performed without a user-specified target.

## Structured priority and scope progress

`priority` replaces the old integer with an object:

```json
{
  "goal_relevance": 0.9,
  "information_gain": 0.8,
  "evidence_value": 0.7,
  "confidence": 0.8,
  "estimated_tokens": 120,
  "estimated_seconds": 2,
  "estimated_requests": 1
}
```

The controller adds `rank`, `score`, `effective_tokens`, `effective_seconds`, `effective_requests`, `expected_benefit`, and `expected_progress_per_1000_tokens`. Benefit combines relevance/information/evidence (0.4/0.3/0.3), confidence, and observed objective progress. Score is benefit per token, discounted by remaining time/request pressure (0.25/0.15). Token cost includes previous planner overhead plus the larger of proposed marginal cost and observed projected-context mean. Time uses the larger of proposed and observed duration. These are explicit heuristics, not a guarantee of global optimality or a fixed tool order.

Actual provider token usage remains the accounting measure. Marginal context cost uses the tokenizer on the same compact evidence projection sent to the model, with a labeled UTF-8 fallback. Full proof/response bytes are not charged as model context estimates. Estimated request count is a ranking signal, not a packet meter or separate enforced request budget. IDOR requires two available call units before either identity request. Expected evidence value/confidence does not verify a vulnerability.

Large scope is represented by `scope_manifest` (explicit units, pinned domains, compressed CIDRs). Each planning window scales with remaining tool/pass/token context budgets. The model may set `advance_scope` with empty actions to defer its current window and consider the next one. It may also stop when the goal is satisfied; remaining scope is reported explicitly. Detailed evidence is retained when the model context is compacted.

Reports include `scope_progress`, `planning_history`, `tool_profiles` and `action_outcomes`. `touched` means an action was attempted, not that all vulnerabilities were evaluated. Budget exhaustion or untouched scope produces `completed_partial`, including counts of untouched/deferred/unprocessed target units. New grants use compact format v2; existing v1 grants remain valid for their signed scope. The `verify_grant` compatibility helper now returns explicit pinned IPs only; use `verify_scope_grant` for network declarations.

A live Qwen3 run selected from 80 seed URLs with a two-call budget, checked two URLs and retained 78 untouched URLs in the report. Its forecast was corrected from observed context size/duration; two planner calls used 2863 reported tokens. This is runtime evidence of staged execution and cost feedback, not proof of globally optimal token use. Evidence: `artifacts/budget-priority-audit/summary.json` and `artifacts/runtime/budget-priority-audit.log`.

Review and stage `config/scope.yaml` together with the source/tests/docs when committing this revision. Signing keys and runtime evidence remain excluded from Git. No commit or push was performed.

The wall-clock agent budget begins after scope approval; local grant/DNS preparation is separate. Scope authorization and blocking OS calls can still incur setup latency. Cost forecasts guide selection but are not guarantees of exact future token/time/request usage.


## Roadmap Iterasi 1-6 completion

See `ROADMAP_ACCEPTANCE.md` for the acceptance matrix, repeatable lab runner, dependency lock, evidence replay and commit instructions. IDOR confirmation now requires operator-supplied private-object ownership and distinct valid lab identities; full sanitized request/response comparison is retained. Generic verification records require worker signatures, complete trace and matching run identity. Model retries/cache are bounded and provider usage is separated from failed-call reservations.

## Product-focus remediation, 2026-10-15

Latest/current-action evidence is prioritized before context compaction; first-64/first-32 observation slicing was removed. Complete evidence stays in artifacts. Nuclei execution identity includes its semantic profile, allowing a changed relevant technology to justify another scan while blocking identical completed profiles.

Decisions request typed `review`: goal status, evidence references, uncertainty, failure, and decision change. The controller grounds it in stored objective-specific evidence. Forged references and unsupported success trigger bounded corrective replanning before execution. Schema repair uses safe field/type feedback and consumes the same budget/ledger. Legacy text clients remain compatible with an explicitly labeled controller-grounded assessment. Once supported objective evidence is sufficient, the model still reviews it with smaller context and output limits.

New records are not automatically goal progress. Verified/refuted authorization proof, uncertain authentication, technology discovery, and generic observations receive different feedback. Nuclei risk comes from exact template content, with isolated single-use active manifest approvals and explicit partial coverage. See `NMAP_NUCLEI_COVERAGE.md` and `PRODUCT_FOCUS_FIX.md`.

For `ollama_chat/`, the installed runtime enforces the decision JSON Schema natively; schema text is omitted from the system prompt. The model must return typed review, including a nonempty next choice even when stopping. Unsupported navigation success receives concrete feedback that discovering a link is different from visiting its destination. A rejected review remains in audit history but is not fed back as a factual previous conclusion. Response-side technology matchers mentioning Interactsh do not constitute outgoing OAST; outgoing execution fields remain inspected and interaction support stays disabled.
