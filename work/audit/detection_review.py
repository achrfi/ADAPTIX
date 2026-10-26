"""Read-only audit of code paths and existing run metadata; no targets or models called."""
import ast
from collections import Counter
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / 'work/audit/detection-review'


def read_report(path):
    if path.stat().st_size > 8_000_000:
        return {'path': str(path.relative_to(ROOT)), 'review': 'skipped_size_limit'}
    try:
        report = json.loads(path.read_text())
    except (ValueError, UnicodeError):
        return {'path': str(path.relative_to(ROOT)), 'review': 'invalid_json'}
    if not isinstance(report, dict):
        return {'path': str(path.relative_to(ROOT)), 'review': 'invalid_shape'}
    is_inventory = isinstance(report.get('endpoints'), list) and 'stages' in report
    verified = report.get('verified_findings', [])
    by_class = Counter(str(row.get('finding_type') or row.get('category') or 'unspecified')
                       for row in verified if isinstance(row, dict))
    methods = Counter(str(row.get('verification_method') or 'unspecified')
                      for row in verified if isinstance(row, dict))
    row = {'path': str(path.relative_to(ROOT)),
           'report_sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
           'schema': 'local_inventory' if is_inventory else 'adaptive_or_review',
           'status': report.get('status'), 'mode': report.get('mode'),
           'review_only': report.get('operator_recon_review_only', False),
           'stop_reason': report.get('stop_reason'),
           'reported_verified_count': len(verified),
           'reported_verified_by_class': dict(by_class),
           'verification_methods': dict(methods),
           'candidates': len(report.get('candidates', [])),
           'probe_traces': len(report.get('probe_traces', [])),
           'nuclei_selections': len(report.get('nuclei_template_selections', [])),
           'browser_test_actions': sum(action.get('tool') == 'browser_test'
                                       for action in report.get('planned_actions', []) if isinstance(action, dict)),
           'error_count': len(report.get('errors', [])),
           'provenance_note': 'Stored report metadata only; scanner labels are not independently revalidated here.'}
    if is_inventory:
        stages = report['stages']
        browser = stages.get('playwright', {})
        row.update(stages={name: value.get('status') for name, value in stages.items()},
                   inventory_records=len(report['endpoints']),
                   observed_records=sum(bool(item.get('observed')) for item in report['endpoints']),
                   browser_pages=browser.get('pages'), browser_requests=browser.get('requests_sent'),
                   finding_schema_present='verified_findings' in report,
                   assessment_interpretation='Vulnerability validation is not performed by this workflow.')
    else:
        metrics = report.get('metrics', {})
        row['tool_calls'] = metrics.get('tool_calls_used', 0)
        row['tool_calls_by_tool'] = metrics.get('tool_calls_by_tool', {})
        row['nuclei_scan_phase'] = {key: value for key, value in metrics.get('nuclei_scan_phase', {}).items()
                                  if key in ('mode', 'completed', 'stop_reason', 'origins_scanned', 'tool_calls')}
        row['approval_results'] = dict(Counter(item.get('result', 'unknown')
                                             for item in report.get('approval_audit', [])))
        row['model_calls'] = metrics.get('llm_calls', 0)
        row['imported_ffuf_rows'] = len(report.get('ffuf_observations', []))
    return row


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    inventory, syntax_errors = [], []
    for directory in ('src', 'tests', 'config', 'lab', 'scripts', 'docs', 'templates'):
        for path in sorted((ROOT / directory).rglob('*')):
            if not path.is_file() or '__pycache__' in path.parts or path.suffix not in (
                    '.py', '.yaml', '.md', '.sh', '.service', '.timer'):
                continue
            raw = path.read_bytes()
            row = {'path': str(path.relative_to(ROOT)), 'sha256': hashlib.sha256(raw).hexdigest(),
                   'bytes': len(raw)}
            if path.suffix == '.py':
                try:
                    tree = ast.parse(raw)
                    row['test_functions'] = sum(isinstance(node, ast.FunctionDef) and node.name.startswith('test_')
                                                for node in ast.walk(tree))
                except SyntaxError as exc:
                    syntax_errors.append({'path': row['path'], 'line': exc.lineno})
            inventory.append(row)
    for name in ('pyproject.toml', 'requirements.lock', 'langgraph.json', 'workflow.mmd'):
        path = ROOT / name
        raw = path.read_bytes()
        inventory.append({'path': name, 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()})
    paths = set((ROOT / 'artifacts/scans').glob('*/report-*.json'))
    paths.update((ROOT / 'work/local-recon-runs').glob('*/report.json'))
    paths.update((ROOT / 'work/ffuf-import-runs').glob('*/project/artifacts/scans/*/report-*.json'))
    reports = [read_report(path) for path in sorted(paths)]
    summary = {'network_requests': 0, 'model_calls_in_audit': 0, 'source_files': len(inventory),
               'python_files': sum(row['path'].endswith('.py') for row in inventory),
               'syntax_errors': syntax_errors, 'stored_reports_read': len(reports),
               'local_inventory_reports': sum(row.get('schema') == 'local_inventory' for row in reports),
               'review_only_reports': sum(bool(row.get('review_only')) for row in reports),
               'reports_with_reported_verified_findings': sum(row.get('reported_verified_count', 0) > 0 for row in reports)}
    (OUT / 'source-inventory.json').write_text(json.dumps(inventory, indent=2) + '\n')
    (OUT / 'run-metadata.json').write_text(json.dumps(reports, indent=2) + '\n')
    (OUT / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps(summary, indent=2))
    known = [row for row in reports if any(name in row['path'] for name in (
        'reference-live-20261024', 'main-entry-check-20261024', '20261023T155531Z-659e19'))]
    print(json.dumps({'known_validation_runs': known}, indent=2))


if __name__ == '__main__':
    main()
