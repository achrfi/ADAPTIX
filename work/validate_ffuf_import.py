"""Run the production graph on saved operator evidence with a real local model."""
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import sys
import uuid

ROOT = Path(__file__).resolve().parents[1]
os.environ.setdefault('LITELLM_LOCAL_MODEL_COST_MAP', 'True')
os.environ['LANGSMITH_TRACING'] = 'false'


def main():
    label = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + uuid.uuid4().hex[:6]
    output = ROOT / 'work/ffuf-import-runs' / label
    project = output / 'project'
    project.mkdir(parents=True)
    for folder in ('src', 'config', 'templates'):
        shutil.copytree(ROOT / folder, project / folder,
                        ignore=shutil.ignore_patterns('__pycache__', '*.pyc', '.adaptix_scope_signing_key'))
    shutil.copy2(ROOT / 'requirements.lock', project / 'requirements.lock')
    sys.path.insert(0, str(project))
    from src.adaptix.processing.ffuf import load_ffuf_files
    from src.adaptix.workflow.graph import graph
    from src.adaptix.agents import planner
    from src.adaptix.tools import registry
    from src.adaptix.evidence.audit import inspect_bundle

    # No scanner capabilities are needed for this review. Provider calls stay real.
    def refuse_execution(*args, **kwargs):
        raise AssertionError('A tool execution was attempted during offline import review')
    registry.tool_registry = lambda: {}
    registry.tool_handlers = refuse_execution
    registry.run_tool = refuse_execution
    completion = planner.litellm.completion
    requests = []

    def capture(**kwargs):
        payload = json.loads(kwargs['messages'][1]['content'])
        requests.append(payload)
        (output / 'model-context.json').write_text(json.dumps(payload, indent=2) + '\n')
        return completion(**kwargs)
    planner.litellm.completion = capture
    source = ROOT / 'work/lab3000-runs/20261023T153207Z-7a7b8e/ffuf.json'
    state = {'target': ['http://127.0.0.1:3000'], 'run_id': 'operator-ffuf-review',
             'user_prompt': 'Ringkas observasi ffuf yang diberikan dan jelaskan keterbatasannya. '
                            'Status 200 bukan bukti route atau kerentanan. Jangan jalankan alat.',
             'ffuf_import_documents': load_ffuf_files([source]),
             'llm_model': 'ollama_chat/qwen3.5:9b-q4_K_M',
             'max_iterations': 1, 'tool_call_budget': 2, 'token_budget': 8000,
             'time_budget_seconds': 540, 'llm_timeout_seconds': 240,
             'model_context_tokens': 8192, 'planner_retry_limit': 0,
             'events': [], 'errors': []}
    try:
        print('Invoking production graph: saved ffuf JSON -> real local AI -> report', flush=True)
        result = graph.invoke(state, config={'recursion_limit': 30})
        report = result['report']
        assert requests and len(requests[0]['observations']['ffuf_observations']) == 6
        assert len(result['ffuf_observations']) == len(report['ffuf_observations']) == 6
        assert result['planner_metrics']['llm_calls'] >= 1
        assert result['planner_metrics']['mode'] == 'llm'
        assert not result.get('attempted_actions')
        assert result['metrics']['tool_calls_used'] == 0
        assert not result['verified_findings'] and not result['errors']
        assert result['operator_recon_review_only'] is True
        assert result['baseline_recon']['mode'] == 'disabled'
        integrity = inspect_bundle(result['artifact_bundle']['evidence-index'])
        summary = {'status': 'passed', 'mode': 'operator_import_review', 'observations': 6,
                   'model': state['llm_model'], 'real_model_calls': result['planner_metrics']['llm_calls'],
                   'model_tokens': result['planner_metrics']['tokens_used'],
                   'executed_tool_calls': 0, 'verified_findings': 0,
                   'report_status': report['status'], 'stop_reason': report['stop_reason'],
                   'self_reflection': report['self_reflection'],
                   'bundle_integrity': integrity['status'],
                   'bundle_files': integrity['files_checked'],
                   'report_path': str(Path(result['artifact_bundle']['report']).relative_to(ROOT))}
    except Exception as exc:
        summary = {'status': 'failed', 'error_type': type(exc).__name__, 'error': str(exc)}
        (output / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
        raise
    (output / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps({'status': summary['status'], 'results': str(output.relative_to(ROOT))}), flush=True)


if __name__ == '__main__':
    main()
