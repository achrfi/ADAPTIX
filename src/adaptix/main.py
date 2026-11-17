"""python -m src.adaptix.main --target 127.0.0.1"""
import argparse
import json
import os
import signal
import sys
import uuid
from pathlib import Path
from src.adaptix.config import ROOT, load_dotenv
from src.adaptix.tools.registry import tool_registry
from src.adaptix.security.authorization import authorize_cli_targets
from src.adaptix.workflow.budget import parse_budget, unlimited_remote_risk
from src.adaptix.evidence.checkpoint import (open_checkpoint, pending_nodes,
                                                 resumable_snapshot, restore_runtime_secrets,
                                                 thread_id_for)

# Engine transport parameter, not an execution budget: LangGraph requires an
# integer recursion limit and unlimited cumulative budgets cannot be expressed
# through it, so unlimited mode asks for the process-int maximum. Every real
# termination in unlimited mode comes from progress/accounting logic in the
# graph itself (stagnation, provider failures, cancellation), never from this
# transport number.
# Limit and progress knobs a resumed process may legitimately change. They are written
# onto the fork point; everything else comes from the checkpoint.
BUDGET_KNOBS = ('tool_call_budget', 'token_budget', 'time_budget_seconds', 'max_iterations',
                'execution_metrics')

ENGINE_RECURSION_LIMIT = 2_147_483_000


# Usage counters that measure spend against a budget. A resume issues a new budget, so
# these restart; the run's earlier totals are kept under the history key.
_USAGE_COUNTERS = ('tool_calls_used', 'tokens_used', 'iterations_used', 'tool_calls_by_phase')


def _prior_usage(values):
    """Spend recorded by the process that wrote the checkpoint, if any."""
    metrics = (values or {}).get('execution_metrics') or {}
    spent = {name: metrics[name] for name in _USAGE_COUNTERS if name in metrics}
    spent['history'] = list(metrics.get('history') or [])
    return spent


def _reset_usage_counters(metrics, previous=None):
    """Return `metrics` with the live usage counters cleared and the old totals archived.

    Called on resume only. Without it the counters keep their value from the earlier
    process while `tool_call_budget` is replaced, so a report compares a new limit
    against the old spend and claims a budget was exceeded when it was not.
    """
    metrics = dict(metrics or {})
    if previous:
        archived = dict(previous)
        archived['resumed_at'] = metrics.get('resumed_at') or None
        metrics['history'] = list(metrics.get('history') or []) + [archived]
    metrics['tool_calls_used'] = 0
    metrics['tokens_used'] = 0
    metrics['iterations_used'] = 0
    metrics.pop('tool_calls_by_phase', None)
    metrics['by_tool'] = {}
    metrics['resumed'] = True
    return metrics

def _env_budget(name, fallback, caster=int):
    """Default a budget from the environment, falling back to a literal.

    `.env` is loaded before the parser is built, so an operator can keep the
    provider and budget settings in one place instead of retyping flags. A bad
    value is not swallowed: it raises, and argparse reports it against the flag.
    """
    raw = os.getenv(name)
    if raw is None or str(raw).strip() == '':
        return fallback
    try:
        return parse_budget(str(raw).strip(), caster)
    except (TypeError, ValueError):
        return raw


def build_arg_parser():
    parser = argparse.ArgumentParser(description='ADAPTIX main CLI (authorized targets only)')
    parser.add_argument('--instruction', required=False, help='Free natural-language research objective')
    parser.add_argument('--identity-context', help='Private JSON: two sessions, identity check URL/path and private-field policy; no scenarios required')
    parser.add_argument('--idor-scenarios', help='JSON file with operator-supplied two-identity scenarios')
    parser.add_argument('--target', action='append', help='Host, IP, CIDR, or domain; repeatable')
    parser.add_argument('--grant', default=os.getenv('ADAPTIX_SCOPE_GRANT'), help='Signed scope grant file issued by local operator')
    parser.add_argument('--principal', default=os.getenv('ADAPTIX_PRINCIPAL'), help='Identity bound into signed grant')
    parser.add_argument('--check-tools', action='store_true')
    parser.add_argument('--check-model', action='store_true',
                        help='Preflight the configured provider (--model/--api-base/--api-key): one planner-shaped '
                             'call, prints pass/fail plus the reason, spends no scan budget and writes no artifact')
    parser.add_argument('--model-context-tokens', type=int, default=_env_budget('ADAPTIX_MODEL_CONTEXT_TOKENS', 4096), help='Maximum input and reserved output context per planner call (stays finite: a model capability, not a budget)')
    parser.add_argument('--local-recon', action='store_true',
                        help='Run loopback ffuf + Playwright inventory through main; use --local-recon --help for its options')
    parser.add_argument('--ffuf-results', action='append', default=[], metavar='FILE',
                        help='Import operator-produced ffuf JSON; repeatable. Review-only by default: '
                             'no scanner or tool execution, offline evidence review')
    parser.add_argument('--ffuf-into-assessment', action='store_true',
                        help='Explicitly release imported ffuf observations to the adaptive pentest graph as '
                             'UNVERIFIED inventory seeds (provenance only, route_existence_verified=false); '
                             'requires --ffuf-results. Without this flag imports stay review-only. Scope, budget, '
                             'policy and evidence contracts still apply; no payloads or tools are added')
    parser.add_argument('--model', default=os.getenv('ADAPTIX_LLM_MODEL', 'ollama_chat/qwen3:14b'), help='LiteLLM model; local Ollama by default')
    parser.add_argument('--api-base', default=os.getenv('ADAPTIX_API_BASE'), help='Provider base URL (LiteLLM api_base); defaults to the provider library routing')
    parser.add_argument('--api-key', default=os.getenv('ADAPTIX_API_KEY'), help='Provider API key for hosted models (kept out of reports; never logged)')
    parser.add_argument('--native-json', choices=('auto', 'on', 'off'), help='Structured-output mode: auto/conservative family detect (default), forced on/off for compatible or unusual providers')
    parser.add_argument('--reasoning-effort', choices=('none', 'low', 'medium', 'high'),
                        default=os.getenv('ADAPTIX_REASONING_EFFORT'),
                        help='Reasoning budget hint for reasoning models. "none" stops a model spending the '
                             'whole output budget on hidden reasoning and returning empty content; the default '
                             'is "none" for Ollama and unset elsewhere')
    parser.add_argument('--temperature', type=float, default=0.2, help='Explicit model sampling temperature, 0-2')
    parser.add_argument('--max-iterations', type=lambda s: parse_budget(s, int), default=_env_budget('ADAPTIX_MAX_ITERATIONS', None),
                        help='Planning-pass budget (finite number or "unlimited"); defaults to the tool-call budget')
    parser.add_argument('--time-budget', type=lambda s: parse_budget(s, float), default=_env_budget('ADAPTIX_TIME_BUDGET', 1800, float),
                        help='Wall-clock run budget in seconds (finite number or "unlimited")')
    parser.add_argument('--tool-call-budget', type=lambda s: parse_budget(s, int), default=_env_budget('ADAPTIX_TOOL_CALL_BUDGET', 20),
                        help='Cumulative executed tool calls (finite number or "unlimited")')
    parser.add_argument('--token-budget', type=lambda s: parse_budget(s, int), default=_env_budget('ADAPTIX_TOKEN_BUDGET', 50000),
                        help='Cumulative model tokens (finite number or "unlimited")')
    parser.add_argument('--planner-retries', type=int, default=1, help='Additional bounded model attempts, 0-3')
    parser.add_argument('--llm-timeout', type=float, default=None,
                        help='Per-call provider window in seconds; bounded by the run time budget and ADAPTIX_LLM_TIMEOUT')
    parser.add_argument('--lab-manifest', help='Operator lab snapshot and ground-truth manifest JSON')
    parser.add_argument('--action-approval', action='append', default=[], help='Signed approval for a state-changing capability')
    parser.add_argument('--no-baseline', action='store_true',
                        help='Disable deterministic baseline reconnaissance (research configuration A: fully LLM-driven recon)')
    parser.add_argument('--wordlist', default=os.getenv('ADAPTIX_WORDLIST'), metavar='FILE_OR_PROFILE',
                        help='Static discovery wordlist: a bundled profile name (common, raft-small-dirs, api, backup) '
                             'or a path relative to the project root; defaults to config/baseline.yaml')
    parser.add_argument('--no-scanner', action='store_true',
                        help='Disable the automatic Nuclei scan phase (research modes: adaptive-only or recon under the same budgets)')
    parser.add_argument('--assessment', action='store_true',
                        help='Operator-authorized Nuclei vulnerability-assessment templates: observation-adjacent active checks (sqli/xss/exposures) still exact-manifest approved, destructive/out-of-band classes always denied')
    parser.add_argument('--no-report-model', action='store_true',
                        help='Render the report without a model-written narrative; recorded findings and evidence stay unchanged')
    parser.add_argument('--run-id', help='Operator-chosen run identity for replay/audit and exact action approval')
    parser.add_argument('--resume', metavar='RUN_ID',
                        help='Continue a run that stopped at a checkpoint instead of starting over: '
                             'reuses the run directory and its evidence, re-runs only the phases the '
                             'previous process did not finish. Requires that run\'s checkpoint database, '
                             'which holds sanitized state only')
    parser.add_argument('--confirm-unlimited-remote', action='store_true',
                        help='Explicit operator confirmation that allows unlimited cumulative budgets on a remote or paid provider')
    return parser


def _run_model_preflight(args):
    """Print the provider preflight result; exit 0 only when the model can plan.

    Kept out of `main` so the smoke check is one call that a test can drive, and
    so a failed preflight never leaves a half-built graph behind.
    """
    from src.adaptix.agents.provider_probe import probe
    from src.adaptix.agents.planner import model_native_supported, OUTPUT_ENVELOPES
    # Probe in the transport mode the planner will actually use. Sending
    # json_object while the planner sends json_schema is how a passing preflight
    # preceded a failing run: the gateway accepted the schema, ignored it, and let
    # the model overflow the cap mid-object.
    state_view = {'llm_native_json': args.native_json or None}
    native_schema = model_native_supported(args.model, state_view)
    envelope = int(OUTPUT_ENVELOPES[0]['tokens'])
    report = probe(args.model, api_base=args.api_base, api_key=args.api_key,
                   native_json=None if args.native_json is None else args.native_json == 'on',
                   timeout=args.llm_timeout or 90.0, temperature=0.0,
                   max_tokens=envelope, context_tokens=args.model_context_tokens,
                   strict_schema=native_schema)
    report['transport'] = 'json_schema' if native_schema else 'json_object'
    print(json.dumps(report, indent=2, ensure_ascii=False))
    for warning in report.get('warnings') or []:
        print(f'\nWARN  {warning}', file=sys.stderr)
    if report['ok']:
        print(f"\nPASS  {args.model} answered with a valid planner decision in "
              f"{report['seconds']}s ({report['output_tokens']} output tokens).")
        return 0
    print(f"\nFAIL  {args.model} cannot serve as this run's planner:", file=sys.stderr)
    for problem in report['problems']:
        print(f'  - {problem}', file=sys.stderr)
    print('\nNothing was scanned and no artifact was written. Fix the above, then re-run '
          '--check-model before starting an assessment.', file=sys.stderr)
    return 1


def run_stream(graph, state, config, cancelled, seed=None):
    """Invoke the graph one node at a time, returning the merged state.

    Merging node updates reproduces graph.invoke's final state while letting an
    operator break the run between nodes: ``cancelled`` is a zero-argument
    callable checked after every node. Cancellation is therefore graceful - the
    in-flight node finishes under its own bounded timeout, no new node starts,
    and the caller still receives a complete partial report from the merged
    checkpoints the run already wrote.
    """
    merged = dict(seed if seed is not None else state)
    # LangGraph's default `updates` mode yields one mapping per node
    # (``{node_name: delta}``), which is not the run state and made the CLI print
    # an empty report. `values` yields complete state snapshots, so the final
    # snapshot (or the last one before cancellation) is the authoritative merge.
    for update in graph.stream(None if seed is not None else state, config=config,
                               stream_mode='values'):
        if isinstance(update, dict):
            merged = {**merged, **update}
            if seed is not None and isinstance(update.get('execution_metrics'), dict):
                # LangGraph replays the thread's earlier snapshots before it runs the
                # next node, and those carry the PREVIOUS process's usage totals. A
                # resumed run reset those counters because it was given a new budget,
                # so a replayed snapshot must not put the old spend back: the report
                # would then measure an earlier run's tool calls against this run's
                # limit. Node spend from THIS process is added to the seed below.
                replayed = int((update['execution_metrics'] or {}).get('tool_calls_used', 0) or 0)
                baseline = int((seed.get('execution_metrics') or {}).get('tool_calls_used', 0) or 0)
                if replayed < baseline:
                    merged['execution_metrics'] = dict(update['execution_metrics'],
                                                       tool_calls_used=baseline)
        if cancelled():
            break
    return merged


def resolve_wordlist(value):
    """Map an operator wordlist selection to a project-relative path.

    A bundled profile name is expanded here so the CLI surface stays small; any
    other value is treated as a path that must stay inside the project tree (the
    adapter re-validates it, so a model-authored value can never widen the read).
    """
    if not value:
        return None
    from src.adaptix.tools.static_discovery import PROFILES
    name = str(value).strip()
    if name in PROFILES:
        return f'work/wordlists/discovery/{PROFILES[name]["file"]}'
    candidate = (ROOT / name).resolve() if not os.path.isabs(name) else Path(name).resolve()
    if not candidate.is_relative_to(ROOT.resolve()):
        raise ValueError(f'--wordlist must stay inside the project tree: {name}')
    if not candidate.is_file():
        raise ValueError(f'--wordlist not found: {name} (or use a profile: {", ".join(sorted(PROFILES))})')
    return str(candidate.relative_to(ROOT.resolve()))


def main(argv=None):
    import math
    # Before the parser is built: every provider default below is read from the
    # environment, so a key that only exists in `.env` must be in os.environ by
    # then. Real environment variables still win (load_dotenv never overrides).
    load_dotenv()
    argv = list(sys.argv[1:] if argv is None else argv)
    if '--local-recon' in argv:
        from src.adaptix.local_inventory.cli import main as recon_main
        return recon_main([argument for argument in argv if argument != '--local-recon'])
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    if args.check_tools:
        print(json.dumps(tool_registry(), indent=2))
        return
    if args.check_model:
        return _run_model_preflight(args)
    if args.max_iterations is None and args.tool_call_budget is not None:
        args.max_iterations = args.tool_call_budget
    if not math.isfinite(args.temperature) or not 0 <= args.temperature <= 2:
        parser.error('temperature must be finite and between 0 and 2')
    if not 0 <= args.planner_retries <= 3:
        parser.error('planner retries must be between 0 and 3')
    if args.llm_timeout is not None and not math.isfinite(args.llm_timeout):
        parser.error('llm timeout must be finite')
    if args.time_budget is not None and (not math.isfinite(args.time_budget) or args.time_budget <= 0):
        parser.error('time budget must be positive')
    for name, value in (('max-iterations', args.max_iterations), ('tool-call-budget', args.tool_call_budget),
                        ('token-budget', args.token_budget)):
        if value is not None and value < 1:
            parser.error(f'{name} must be positive or "unlimited"')
    if args.model_context_tokens < 1:
        parser.error('model-context-tokens must be positive')
    # Unlimited is a local-development arrangement: a remote or paid provider
    # never silently inherits an uncapped spend. An explicit flag confirms the
    # operator means it.
    if any(value is None for value in (args.time_budget, args.tool_call_budget, args.token_budget, args.max_iterations)):
        if unlimited_remote_risk(args.model, args.api_base, args.api_key) and not args.confirm_unlimited_remote:
            parser.error('unlimited budgets are only allowed on the default local provider; pass '
                         '--confirm-unlimited-remote to accept uncapped spending on a remote or paid provider explicitly')
    if not args.target and getattr(args, 'resume', None):
        # A resume continues work that already had a target, and that target is in the
        # checkpoint. Demanding it again was pure friction -- but the target is also the
        # authorization boundary, so it is never taken silently: the value from the
        # checkpoint is used only when the operator named none, and it is reported. A
        # differing --target still wins, because widening or narrowing scope is the
        # operator's decision, not an artifact's.
        inherited = None
        try:
            point = resumable_snapshot(args.resume)
            inherited = (point.values or {}).get('target') if point is not None else None
        except Exception:
            inherited = None
        if inherited:
            args.target = list(inherited) if isinstance(inherited, (list, tuple)) else [inherited]
            args._target_from_checkpoint = True
            print(f'resume {args.resume}: target inherited from its checkpoint '
                  f'({", ".join(map(str, args.target))}); pass --target to override', flush=True)
        elif point is None:
            # Nothing to inherit because there is no checkpoint. Saying "--target is
            # required" here sends the operator to add a flag that would not help.
            parser.error(f'--resume {args.resume}: no resumable checkpoint for that run '
                         f'(start it normally first, or it already completed)')
    if not args.target:
        parser.error('--target is required unless --check-tools is used')
    from src.adaptix.processing.ffuf import load_ffuf_files
    try:
        ffuf_documents = load_ffuf_files(args.ffuf_results)
    except (OSError, ValueError) as exc:
        parser.error('ffuf import: ' + str(exc))
    if args.ffuf_into_assessment and not ffuf_documents:
        parser.error('--ffuf-into-assessment requires at least one --ffuf-results file')
    instruction = args.instruction or input('Tujuan pengujian: ')
    # A one-hour grant against a two-hour budget guarantees the loop dies with
    # authorization_invalid while evidence is still being gathered. The grant
    # covers the run it authorizes, with a bounded cushion for planning passes
    # that finish just past the deadline.
    grant_hours = 1
    if args.time_budget is not None:
        grant_hours = min(168, max(1, math.ceil(args.time_budget / 3600) + 1))
    elif args.confirm_unlimited_remote or args.time_budget is None:
        grant_hours = 8
    try:
        grant, principal = authorize_cli_targets(args.target, args.principal, args.grant,
                                                 hours=grant_hours)
    except (ValueError, OSError) as exc:
        parser.error(str(exc))
    try:
        recon_wordlist = resolve_wordlist(args.wordlist)
    except ValueError as exc:
        parser.error(str(exc))
    from src.adaptix.workflow.graph import graph, resumable_graph
    resume_run_id = str(args.resume).strip() if args.resume else None
    if resume_run_id and args.run_id and args.run_id != resume_run_id:
        parser.error('--resume and a different --run-id disagree about which run this is')
    if resume_run_id and not pending_nodes(resume_run_id):
        parser.error(f'--resume {resume_run_id}: no resumable checkpoint for that run '
                     f'(start it normally first, or it already completed)')
    state = {'target': args.target,
             'grant': grant, 'principal': principal,
             'run_id': resume_run_id or args.run_id or uuid.uuid4().hex[:12],
             'events': [], 'errors': [],
             'user_prompt': instruction,
             'ffuf_import_documents': ffuf_documents,
             'ffuf_into_assessment': bool(args.ffuf_into_assessment),
             'identity_context': json.load(open(args.identity_context, encoding='utf-8')) if args.identity_context else {},
             'idor_scenarios': json.load(open(args.idor_scenarios, encoding='utf-8')) if args.idor_scenarios else [],
             'llm_model': args.model, 'max_iterations': args.max_iterations,
             'llm_temperature': args.temperature,
             'model_context_tokens': args.model_context_tokens,
             'planner_retry_limit': args.planner_retries, 'action_approvals': args.action_approval,
             'llm_timeout_seconds': args.llm_timeout,
             'lab_manifest': json.load(open(args.lab_manifest, encoding='utf-8')) if args.lab_manifest else {},
             'time_budget_seconds': args.time_budget, 'tool_call_budget': args.tool_call_budget, 'token_budget': args.token_budget,
             'baseline_disabled': bool(args.no_baseline), 'scanner_disabled': bool(args.no_scanner),
             'recon_wordlist': recon_wordlist,
             'llm_api_base': args.api_base or None, 'llm_api_key': args.api_key or None,
             'llm_native_json': args.native_json or None,
             'llm_reasoning_effort': args.reasoning_effort,
             'scanner_assessment': bool(args.assessment),
             'report_model_enabled': not args.no_report_model}
    if args.max_iterations is None or args.tool_call_budget is None:
        recursion_limit = ENGINE_RECURSION_LIMIT
    else:
        recursion_limit = max(50, 10 + args.max_iterations * (args.tool_call_budget * 2 + 5))
    cancelled = {'flag': False}
    previous_int = signal.getsignal(signal.SIGINT)
    previous_term = signal.getsignal(signal.SIGTERM)

    def _cancel(signum, frame):
        cancelled['flag'] = True
    # Every run writes a checkpoint database under its own run directory, so the
    # next process can continue instead of restarting from zero; --resume reuses an
    # existing one. The saver scrubs state before it reaches the disk.
    if resume_run_id:
        with open_checkpoint(state['run_id']) as (saver, _checkpoint_file):
            engine = resumable_graph(saver)
            pending = pending_nodes(resume_run_id)
        if not pending:
            print(f'run {resume_run_id}: nothing resumable (it completed, or never started)')
            return 0
        print(f"resuming run {resume_run_id}: continuing at {' -> '.join(pending)}")

    resume_key = None
    if resume_run_id:
        # The checkpoint stores a placeholder where the provider key was, so the loaded
        # state cannot authenticate. The environment (or --api-key) is the source of
        # truth; with no key the run reports a real provider failure instead of sending
        # a placeholder as a credential.
        resume_key = (args.api_key or os.environ.get('ADAPTIX_API_KEY') or '').strip() or None
    try:
        with open_checkpoint(state['run_id']) as (saver, _checkpoint_file):
            # Every run streams an engine bound to its own checkpoint: a fresh run writes
            # a thread it could later resume, and a resume reads the one already there.
            # `graph` stays the plain, unbound object for callers that only need the
            # graph's shape; durability is a property of the run, not of the module.
            engine = resumable_graph(saver)
            config = {'recursion_limit': recursion_limit,
                      'configurable': {'thread_id': thread_id_for(state['run_id'])}}
            try:
                signal.signal(signal.SIGINT, _cancel)
                signal.signal(signal.SIGTERM, _cancel)
                # A fresh run starts from the operator state. A resume re-enters the
                # thread at the point the previous limit cut short (not at the stopping
                # tail, which has nothing left to do), with this process's budgets and a
                # provider key restored from the environment - the file only holds a
                # placeholder, so a resumed run cannot authenticate from disk alone.
                if resume_run_id:
                    point = resumable_snapshot(resume_run_id)
                    if point is None:
                        parser.error(f'--resume {resume_run_id}: no resumable checkpoint for that run '
                                     f'(start it normally first, or it already completed)')
                    # The snapshot carries the *previous* run's limits, and a resume is a
                    # new operator decision. Seeding those knobs back through `input`
                    # would replay the same graph pass from the top; instead write only
                    # the changed knobs onto the fork point, then run the graph forward.
                    # Always write the knobs, even when the value looks unchanged: the
                    # previous process may have stopped on a *derived* reserve, and an
                    # identical-looking value is exactly the case that needs re-asserting.
                    budget_only = {name: state[name] for name in BUDGET_KNOBS if name in state}
                    # The usage counters belong to the budget they were spent against, and
                    # a resume sets a new budget. Carry the old total forward as history and
                    # start the live counters again, or a report would show more used than
                    # configured (the previous run's spend counted against this one's limit).
                    budget_only['execution_metrics'] = _reset_usage_counters(
                        budget_only.get('execution_metrics'), previous=_prior_usage(point.values or {}))
                    seed = restore_runtime_secrets({**(point.values or {}), **budget_only},
                                                   env={'ADAPTIX_API_KEY': resume_key or ''})
                    # Write onto the fork point, but never keep its checkpoint_id for the
                    # run: a pinned id makes every later read return the *pre-write*
                    # snapshot, so the escalated budgets would be invisible.
                    #
                    # The key has to go through the same write. LangGraph reads channel
                    # values from the checkpoint, so a key restored into a local dict is
                    # overwritten by the placeholder the moment the node runs. The write
                    # passes through the sanitizing saver, which stores only the marker -
                    # the credential stays out of the file for good.
                    updates = dict(budget_only)
                    if resume_key:
                        updates['llm_api_key'] = resume_key
                    at_point = {'configurable': dict(point.config['configurable'])}
                    if updates:
                        engine.update_state(at_point, updates, as_node=point.next[0])
                    # Run from the thread head so the graph continues after the node the
                    # write recorded, with this process's limits in force.
                    fork = {**config, 'configurable': {'thread_id': config['configurable']['thread_id']}}
                    result = run_stream(engine, None, config=fork,
                                        cancelled=lambda: cancelled['flag'], seed=seed)
                else:
                    # A fresh run streams the module-level graph: it is the object every
                    # caller instruments, and the checkpoint for this run is written by
                    # the saver attached to it below rather than by a look-alike copy.
                    result = run_stream(engine, state, config=config,
                                        cancelled=lambda: cancelled['flag'])
            finally:
                signal.signal(signal.SIGINT, previous_int)
                signal.signal(signal.SIGTERM, previous_term)
    except KeyboardInterrupt:
        result = {'stop_reason': 'operator_cancelled'}
    if cancelled['flag'] or result.get('stop_reason') == 'operator_cancelled':
        if not result.get('report'):
            from src.adaptix.workflow.nodes import final_report
            result = final_report({**result, 'stop_reason': 'operator_cancelled'})
        if not result.get('events'):
            from src.adaptix.workflow.events import log
            result['events'] = log(result, 'Final Report: operator_cancelled')
        if 'status' in result:
            result['status'] = 'operator_cancelled'
    print('=== EXECUTION RESULT ===')
    display_report = dict(result.get('report', {}))
    print(json.dumps(display_report, indent=2, ensure_ascii=False, allow_nan=False))
    print('\n=== WORKFLOW EVENTS ===')
    for event in result.get('events', []):
        print('[EVENT]', event)
    if result.get('artifact_bundle'):
        print('\nAudit bundle:', json.dumps(result['artifact_bundle'], ensure_ascii=False))


if __name__ == '__main__':
    raise SystemExit(main())
