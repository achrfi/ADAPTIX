"""python -m src.adaptix.main --target 127.0.0.1 --authorized"""
import argparse
import json
import uuid
import os
from src.adaptix.tools.registry import tool_registry


def main():
    parser = argparse.ArgumentParser(description='ADAPTIX main CLI (authorized targets only)')
    parser.add_argument('--target', action='append', help='Host, IP, CIDR, or domain; repeatable')
    parser.add_argument('--authorized', action='store_true', help='Confirm permission for targets')
    parser.add_argument('--grant', help='Signed scope grant file issued by local operator')
    parser.add_argument('--principal', help='Identity bound into signed grant')
    parser.add_argument('--check-tools', action='store_true')
    parser.add_argument('--model', default=os.getenv('ADAPTIX_LLM_MODEL', 'ollama/qwen2.5:7b'), help='LiteLLM model; local Ollama by default')
    parser.add_argument('--max-iterations', type=int, default=3)
    parser.add_argument('--tool-call-budget', type=int, default=20)
    parser.add_argument('--token-budget', type=int, default=50000)
    args = parser.parse_args()
    if args.check_tools:
        print(json.dumps(tool_registry(), indent=2))
        return
    if min(args.max_iterations, args.tool_call_budget, args.token_budget) < 1:
        parser.error('budget values must be positive')
    if not args.target:
        parser.error('--target is required unless --check-tools is used')
    from src.adaptix.workflow.graph import graph
    state = {'target': args.target, 'authorization_confirmed': args.authorized,
             'grant': args.grant, 'principal': args.principal,
             'run_id': uuid.uuid4().hex[:12], 'events': [], 'errors': [],
             'llm_model': args.model, 'max_iterations': args.max_iterations,
             'tool_call_budget': args.tool_call_budget, 'token_budget': args.token_budget}
    result = graph.invoke(state, config={'recursion_limit': max(50, 10 + args.max_iterations * (args.tool_call_budget * 2 + 5))})
    print('=== EXECUTION RESULT ===')
    print(json.dumps(result.get('report', {}), indent=2, ensure_ascii=False))
    print('\n=== WORKFLOW EVENTS ===')
    for event in result.get('events', []):
        print('[EVENT]', event)


if __name__ == '__main__':
    main()
