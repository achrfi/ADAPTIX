"""Benign, offline audit probes. No target requests and no real credentials."""
import ast
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
os.environ.setdefault('LITELLM_LOCAL_MODEL_COST_MAP', 'True')


def main():
    from src.adaptix.evidence.sanitize import sanitize, scenario_secrets
    from src.adaptix.security import authorization, action_policy
    from src.adaptix.evidence import audit, storage
    before = ROOT / 'work/audit/before/project/src/adaptix/evidence/sanitize.py'
    spec = importlib.util.spec_from_file_location('before_sanitize', before)
    previous = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(previous)
    marker = 'SYNTHETIC_AUDIT_MARKER_2026'
    result = {'uses_real_credentials': False, 'network_requests': 0,
              'provider_key_redaction_before': previous.sanitize({'llm_api_key': marker})['llm_api_key'] != marker,
              'provider_key_redaction_after': sanitize({'llm_api_key': marker})['llm_api_key'] != marker}
    with tempfile.TemporaryDirectory(prefix='control-', dir=ROOT / 'work/audit') as directory:
        folder = Path(directory)
        authorization.KEY_PATH = folder / 'test-signing-key'
        authorization._key(create=True)
        approval = action_policy.issue_action_approval(
            'audit-offline', 'audit', 'http_request', 'http://127.0.0.1:18080',
            'execute_once', destination=folder / 'approval.json')
        state = {'run_id': 'audit-offline', 'principal': 'audit', 'action_approvals': [str(approval)]}
        action = {'tool': 'http_request', 'target': 'http://127.0.0.1:18080'}
        first = action_policy.approval_for(state, action, {'risk': 'state_change'})
        second = action_policy.approval_for({**state, 'approval_audit': [{**first, 'action': action}]},
                                           action, {'risk': 'state_change'})
        result['approval_reuse_after_recorded_use'] = {'first': first['result'], 'second': second['result']}
        storage.ROOT = folder
        record = {**state, 'llm_api_key': marker, 'errors': ['Provider echoed ' + marker]}
        checkpoint = Path(audit.checkpoint(record)).read_text()
        result['checkpoint_provider_key_absent'] = marker not in checkpoint
    tree = ast.parse((ROOT / 'src/adaptix/workflow/graph.py').read_text())
    schema = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == 'AgentState')
    keys = {node.target.id for node in schema.body if isinstance(node, ast.AnnAssign)}
    result['cli_provider_options_missing_from_graph_schema'] = sorted(
        {'llm_api_base', 'llm_api_key', 'llm_native_json'} - keys)
    # Exercise only schema filtering in a disposable graph; no planner or adapters run.
    from langgraph.graph import END, START, StateGraph
    from src.adaptix.workflow.graph import AgentState
    builder = StateGraph(AgentState)
    builder.add_node('observe_keys', lambda state: {'events': sorted(state)})
    builder.add_edge(START, 'observe_keys')
    builder.add_edge('observe_keys', END)
    filtered = builder.compile().invoke({'llm_api_key': marker, 'llm_api_base': 'http://127.0.0.1:11434',
                                         'llm_native_json': 'on', 'events': []})
    result['provider_options_visible_to_node'] = sorted(
        {'llm_api_base', 'llm_api_key', 'llm_native_json'}.intersection(filtered['events']))
    (ROOT / 'work/audit/control-probes.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
