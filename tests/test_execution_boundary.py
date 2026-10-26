"""A capability's proven record must survive the execution boundary.

Measured defect this locks: `execute_action` accumulated only `services` and
`idor_findings`. `union_extract` wrote its proven-impact finding to `verified_findings`,
the next tool result replaced that list, and a run that had extracted a real password
hash reported two rows with no impact at all.
"""
import ast
import pathlib

SOURCE = pathlib.Path('/root/projects/adaptix/src/adaptix/workflow/nodes.py').read_text()


def test_execute_action_accumulates_every_provable_key():
    tree = ast.parse(SOURCE)
    found = None
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == 'execute_action':
            for inner in ast.walk(node):
                # The tuple of keys merged with the incoming state.
                if isinstance(inner, ast.Tuple) and all(
                        isinstance(elt, ast.Constant) and isinstance(elt.value, str)
                        for elt in inner.elts):
                    values = {elt.value for elt in inner.elts}
                    if 'services' in values:
                        found = values
    assert found is not None, 'the accumulation tuple was not found'
    for key in ('injection_findings', 'script_findings', 'verified_findings',
                'verification_evidence'):
        assert key in found, (key, sorted(found))


def test_the_extraction_writes_where_the_report_reads():
    tool = pathlib.Path(
        '/root/projects/adaptix/src/adaptix/tools/union_extract.py').read_text()
    assert "'verified_findings': verified" in tool, 'the proven record is not exported'
    assert "'impact_proven': True" in tool, 'the impact flag is not on the record'
