"""python -m src.adaptix.main --target 127.0.0.1"""
import argparse
import json
import os
import signal
import uuid
from src.adaptix.tools.registry import tool_registry
from src.adaptix.security.authorization import authorize_cli_targets
from src.adaptix.workflow.budget import parse_budget, unlimited_remote_risk

# Engine transport parameter, not an execution budget: LangGraph requires an
# integer recursion limit and unlimited cumulative budgets cannot be expressed
# through it, so unlimited mode asks for the process-int maximum. Every real
# termination in unlimited mode comes from progress/accounting logic in the
# graph itself (stagnation, provider failures, cancellation), never from this
# transport number.
ENGINE_RECURSION_LIMIT = 2_147_483_000


def build_arg_parser():
    parser = argparse.ArgumentParser(description='ADAPTIX main CLI (authorized targets only)')
    parser.add_argument('--instruction', required=False, help='Free natural-language research objective')
    parser.add_argument('--identity-context', help='Private JSON: two sessions, identity check URL/path and private-field policy; no scenarios required')
    parser.add_argument('--idor-scenarios', help='JSON file with operator-supplied two-identity scenarios')
    parser.add_argument('--target', action='append', help='Host, IP, CIDR, or domain; repeatable')
    parser.add_argument('--grant', default=os.getenv('ADAPTIX_SCOPE_GRANT'), help='Signed scope grant file issued by local operator')
    parser.add_argument('--principal', default=os.getenv('ADAPTIX_PRINCIPAL'), help='Identity bound into signed grant')
    parser.add_argument('--check-tools', action='store_true')
    parser.add_argument('--model', default=os.getenv('ADAPTIX_LLM_MODEL', 'ollama_chat/qwen3:14b'), help='LiteLLM model; local Ollama by default')
    parser.add_argument('--api-base', default=os.getenv('ADAPTIX_API_BASE'), help='Provider base URL (LiteLLM api_base); defaults to the provider library routing')
    parser.add_argument('--api-key', default=os.getenv('ADAPTIX_API_KEY'), help='Provider API key for hosted models (kept out of reports; never logged)')
    parser.add_argument('--native-json', choices=('auto', 'on', 'off'), help='Structured-output mode: auto/conservative family detect (default), forced on/off for compatible or unusual providers')
    parser.add_argument('--temperature', type=float, default=0.2, help='Explicit model sampling temperature, 0-2')
    parser.add_argument('--max-iterations', type=lambda s: parse_budget(s, int), default=None,
                        help='Planning-pass budget (finite number or "unlimited"); defaults to the tool-call budget')
    parser.add_argument('--time-budget', type=lambda s: parse_budget(s, float), default=1800,
                        help='Wall-clock run budget in seconds (finite number or "unlimited")')
    parser.add_argument('--tool-call-budget', type=lambda s: parse_budget(s, int), default=20,
                        help='Cumulative executed tool calls (finite number or "unlimited")')
    parser.add_argument('--token-budget', type=lambda s: parse_budget(s, int), default=50000,
                        help='Cumulative model tokens (finite number or "unlimited")')
    parser.add_argument('--model-context-tokens', type=int, default=4096, help='Maximum input and reserved output context per planner call (stays finite: a model capability, not a budget)')
    parser.add_argument('--planner-retries', type=int, default=1, help='Additional bounded model attempts, 0-3')
    parser.add_argument('--llm-timeout', type=float, default=None,
                        help='Per-call provider window in seconds; bounded by the run time budget and ADAPTIX_LLM_TIMEOUT')
    parser.add_argument('--lab-manifest', help='Operator lab snapshot and ground-truth manifest JSON')
    parser.add_argument('--action-approval', action='append', default=[], help='Signed approval for a state-changing capability')
    parser.add_argument('--no-baseline', action='store_true',
                        help='Disable deterministic baseline reconnaissance (research configuration A: fully LLM-driven recon)')
    parser.add_argument('--no-scanner', action='store_true',
                        help='Disable the automatic Nuclei scan phase (research modes: adaptive-only or recon under the same budgets)')
    parser.add_argument('--assessment', action='store_true',
                        help='Operator-authorized Nuclei vulnerability-assessment templates: observation-adjacent active checks (sqli/xss/exposures) still exact-manifest approved, destructive/out-of-band classes always denied')
    parser.add_argument('--run-id', help='Operator-chosen run identity for replay/audit and exact action approval')
    parser.add_argument('--confirm-unlimited-remote', action='store_true',
                        help='Explicit operator confirmation that allows unlimited cumulative budgets on a remote or paid provider')
    return parser


def run_stream(graph, state, config, cancelled):
    """Invoke the graph one node at a time, returning the merged state.

    Merging node updates reproduces graph.invoke's final state while letting an
    operator break the run between nodes: ``cancelled`` is a zero-argument
    callable checked after every node. Cancellation is therefore graceful - the
    in-flight node finishes under its own bounded timeout, no new node starts,
    and the caller still receives a complete partial report from the merged
    checkpoints the run already wrote.
    """
    merged = dict(state)
    for update in graph.stream(state, config=config):
        if isinstance(update, dict):
            merged = {**merged, **update}
        if cancelled():
            break
    return merged


def main():
    import math
    parser = build_arg_parser()
    args = parser.parse_args()
    if args.check_tools:
        print(json.dumps(tool_registry(), indent=2))
        return
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
    if not args.target:
        parser.error('--target is required unless --check-tools is used')
    instruction = args.instruction or input('Tujuan pengujian: ')
    try:
        grant, principal = authorize_cli_targets(args.target, args.principal, args.grant)
    except (ValueError, OSError) as exc:
        parser.error(str(exc))
    from src.adaptix.workflow.graph import graph
    state = {'target': args.target,
             'grant': grant, 'principal': principal,
             'run_id': args.run_id or uuid.uuid4().hex[:12], 'events': [], 'errors': [],
             'user_prompt': instruction,
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
             'llm_api_base': args.api_base or None, 'llm_api_key': args.api_key or None,
             'llm_native_json': args.native_json or None,
             'scanner_assessment': bool(args.assessment)}
    if args.max_iterations is None or args.tool_call_budget is None:
        recursion_limit = ENGINE_RECURSION_LIMIT
    else:
        recursion_limit = max(50, 10 + args.max_iterations * (args.tool_call_budget * 2 + 5))
    cancelled = {'flag': False}
    previous_int = signal.getsignal(signal.SIGINT)
    previous_term = signal.getsignal(signal.SIGTERM)

    def _cancel(signum, frame):
        cancelled['flag'] = True
    try:
        signal.signal(signal.SIGINT, _cancel)
        signal.signal(signal.SIGTERM, _cancel)
        try:
            result = run_stream(graph, state, config={'recursion_limit': recursion_limit}, cancelled=lambda: cancelled['flag'])
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
    # Keep the full audit/API report; collapse large port scopes only for display.
    display_report = dict(result.get('report', {}))
    ports = display_report.get('scope_ports')
    if isinstance(ports, list) and len(ports) > 128:
        from src.adaptix.security.ports import format_ports
        display_report['scope_ports'] = {'ranges': format_ports(ports), 'count': len(set(ports))}
    print(json.dumps(display_report, indent=2, ensure_ascii=False, allow_nan=False))
    print('\n=== WORKFLOW EVENTS ===')
    for event in result.get('events', []):
        print('[EVENT]', event)
    if result.get('artifact_bundle'):
        print('\nAudit bundle:', json.dumps(result['artifact_bundle'], ensure_ascii=False))


if __name__ == '__main__':
    main()
