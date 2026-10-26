"""A verified object-level authorization finding must carry a triageable severity.

Measured: a confirmed cross-identity read of a private book produced
`severity: "unknown"` in the report, because `idor_findings` rows never carry a
severity field. Every IDOR this tool verifies would have been unfilterable.
"""
import pathlib
import re

SRC = pathlib.Path('src/adaptix/agents/reflector.py').read_text()
BLOCK = SRC[SRC.index("for finding in state.get('idor_findings', [])"):
            SRC.index("for index, row in enumerate(state.get('verification_evidence', [])")]


def test_fallback_is_not_unknown():
    assert "'unknown'" not in BLOCK
    assert "severity': finding.get('severity') or" in BLOCK


def test_severity_is_high_when_proof_exists():
    assert "('high' if proof else 'medium')" in BLOCK


def test_classification_is_cwe_639():
    assert 'CWE-639' in BLOCK


def test_finding_type_is_broken_object_level_authorization():
    assert "'broken_object_level_authorization'" in BLOCK


def test_technical_finding_still_wins():
    """An explicitly supplied severity is never overwritten."""
    assert "finding.get('severity') or" in BLOCK
