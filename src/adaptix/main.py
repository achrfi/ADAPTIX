"""python -m src.adaptix.main --target 127.0.0.1"""
import argparse
import json
import uuid
import os
import math
from src.adaptix.tools.registry import tool_registry
from src.adaptix.security.authorization import authorize_cli_targets


def main():
    parser = argparse.ArgumentParser(description='ADAPTIX main CLI (authorized targets only)')
    parser.add_argument('--instruction', required=False, help='Free natural-language research objective')
    parser.add_argument('--identity-context', help='Private JSON: two sessions, identity check URL/path and private-field policy; no scenarios required')
    parser.add_argument('--idor-scenarios', help='JSON file with operator-supplied two-identity scenarios')
    parser.add_argument('--target', action='append', help='Host, IP, CIDR, or domain; repeatable')
    parser.add_argument('--grant', default=os.getenv('ADAPTIX_SCOPE_GRANT'), help='Signed scope grant file issued by local operator')
    parser.add_argument('--principal', default=os.getenv('ADAPTIX_PRINCIPAL'), help='Identity bound into signed grant')
    parser.add_argument('--check-tools', action='store_true')
    parser.add_argument('--model', default=os.getenv('ADAPTIX_LLM_MODEL', 'ollama_chat/qwen3:14b'), help='LiteLLM model; local Ollama by default')
    parser.add_argument('--temperature', type=float, default=0.2, help='Explicit model sampling temperature, 0-2')
    parser.add_argument('--max-iterations', type=int, default=None, help='Planning-pass budget; defaults to tool-call budget')
    parser.add_argument('--time-budget', type=float, default=1800, help='Wall-clock run budget in seconds')
    parser.add_argument('--tool-call-budget', type=int, default=20)
    parser.add_argument('--token-budget', type=int, default=50000)
    parser.add_argument('--model-context-tokens', type=int, default=4096, help='Maximum input and reserved output context per planner call')
    parser.add_argument('--planner-retries', type=int, default=1, help='Additional bounded model attempts, 0-3')
    parser.add_argument('--llm-timeout', type=float, default=None,
                        help='Per-call provider window in seconds; bounded by the run time budget and ADAPTIX_LLM_TIMEOUT')
    parser.add_argument('--lab-manifest', help='Operator lab snapshot and ground-truth manifest JSON')
    parser.add_argument('--action-approval', action='append', default=[], help='Signed approval for a state-changing capability')
    parser.add_argument('--run-id', help='Operator-chosen run identity for replay/audit and exact action approval')
    args = parser.parse_args()
    if args.check_tools:
        print(json.dumps(tool_registry(), indent=2))
        return
    if args.max_iterations is None:
        args.max_iterations = args.tool_call_budget
    if not math.isfinite(args.time_budget) or args.time_budget <= 0:
        parser.error('time budget must be positive')
    if not math.isfinite(args.temperature) or not 0 <= args.temperature <= 2:
        parser.error('temperature must be finite and between 0 and 2')
    if not 0 <= args.planner_retries <= 3:
        parser.error('planner retries must be between 0 and 3')
    if args.llm_timeout is not None and not math.isfinite(args.llm_timeout):
        parser.error('llm timeout must be finite')
    if min(args.max_iterations, args.tool_call_budget, args.token_budget, args.model_context_tokens) < 1:
        parser.error('budget values must be positive')
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
             'time_budget_seconds': args.time_budget, 'tool_call_budget': args.tool_call_budget, 'token_budget': args.token_budget}
    result = graph.invoke(state, config={'recursion_limit': max(50, 10 + args.max_iterations * (args.tool_call_budget * 2 + 5))})
    print('=== EXECUTION RESULT ===')
    # Keep the full audit/API report; collapse large port scopes only for display.
    display_report = dict(result.get('report', {}))
    ports = display_report.get('scope_ports')
    if isinstance(ports, list) and len(ports) > 128:
        from src.adaptix.security.ports import format_ports
        display_report['scope_ports'] = {'ranges': format_ports(ports), 'count': len(set(ports))}
    print(json.dumps(display_report, indent=2, ensure_ascii=False))
    print('\n=== WORKFLOW EVENTS ===')
    for event in result.get('events', []):
        print('[EVENT]', event)
    if result.get('artifact_bundle'):
        print('\nAudit bundle:', json.dumps(result['artifact_bundle'], ensure_ascii=False))


if __name__ == '__main__':
    main()
