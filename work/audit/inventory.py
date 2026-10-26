"""Offline source/AST and dependency inventory; never reads .env or runtime secrets."""
import ast
from importlib import metadata
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tomllib

ROOT = Path(__file__).resolve().parents[2]
DIRECTORIES = ('src', 'tests', 'config', 'templates', 'lab', 'scripts', 'docs')


def main():
    files, failures = [], []
    for folder in DIRECTORIES:
        for path in sorted((ROOT / folder).rglob('*')):
            if not path.is_file() or '__pycache__' in path.parts or path.name.startswith('.'):
                continue
            if path.suffix not in ('.py', '.yaml', '.toml', '.md', '.sh', '.service', '.timer') and path.name != 'labctl':
                continue
            raw = path.read_bytes()
            row = {'path': str(path.relative_to(ROOT)), 'bytes': len(raw),
                   'sha256': hashlib.sha256(raw).hexdigest()}
            if path.suffix == '.py':
                try:
                    tree = ast.parse(raw)
                    row['functions'] = sum(isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                                           for node in ast.walk(tree))
                    row['test_functions'] = sum(isinstance(node, ast.FunctionDef) and node.name.startswith('test_')
                                                for node in ast.walk(tree))
                except SyntaxError as exc:
                    failures.append({'path': row['path'], 'error': str(exc)})
            files.append(row)
    project = tomllib.loads((ROOT / 'pyproject.toml').read_text())
    names = ('httpx', 'langgraph', 'litellm', 'pydantic', 'PyYAML', 'playwright', 'pytest')
    packages = {name: metadata.version(name) for name in names}
    check = subprocess.run([sys.executable, '-m', 'pip', 'check'], capture_output=True,
                           text=True, check=False, timeout=30)
    result = {'method': 'offline source inventory and AST syntax checks; targeted manual security review recorded in writeup.md',
              'file_count': len(files), 'python_files': sum(row['path'].endswith('.py') for row in files),
              'ast_errors': failures, 'installed_versions': packages,
              'pip_check': {'returncode': check.returncode, 'output': check.stdout.strip()},
              'vulnerability_database_lookup': False,
              'project_dependencies': project['project']['dependencies'], 'files': files}
    (ROOT / 'work/audit/inventory.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({key: result[key] for key in ('file_count', 'python_files', 'ast_errors', 'pip_check')}))


if __name__ == '__main__':
    main()
