"""python -m src.adaptix.main --target 127.0.0.1 --authorized"""
import argparse
import json
import uuid
from src.adaptix.tools.registry import tool_registry


def main():
    parser = argparse.ArgumentParser(description='ADAPTIX main CLI (authorized targets only)')
    parser.add_argument('--target', action='append', help='Host, IP, CIDR, or domain; repeatable')
    parser.add_argument('--authorized', action='store_true', help='Confirm permission for targets')
    parser.add_argument('--grant', help='Signed scope grant file issued by local operator')
    parser.add_argument('--principal', help='Identity bound into signed grant')
    parser.add_argument('--check-tools', action='store_true')
    args = parser.parse_args()
    if args.check_tools:
        print(json.dumps(tool_registry(), indent=2))
        return
    if not args.target:
        parser.error('--target is required unless --check-tools is used')
    from src.adaptix.workflow.graph import graph
    state = {'target': args.target, 'authorization_confirmed': args.authorized,
             'grant': args.grant, 'principal': args.principal,
             'run_id': uuid.uuid4().hex[:12], 'events': [], 'errors': []}
    result = graph.invoke(state, config={'recursion_limit': 30})
    print('=== EXECUTION RESULT ===')
    print(json.dumps(result.get('report', {}), indent=2, ensure_ascii=False))
    print('\n=== WORKFLOW EVENTS ===')
    for event in result.get('events', []):
        print('[EVENT]', event)


if __name__ == '__main__':
    main()
