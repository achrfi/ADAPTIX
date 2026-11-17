"""A resume must not demand a target it already owns.

The defect: `--target is required` was checked before any --resume branch, so
continuing a run meant retyping the target already stored in its checkpoint.

The rule locked here: a target is inherited ONLY when the operator names none --
never silently overriding an explicit --target, because the target is the
authorization boundary -- and a resume with no checkpoint says so instead of
sending the operator after a flag that cannot help.
"""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

MAIN = (ROOT / 'src' / 'adaptix' / 'main.py').read_text()


def test_inheritance_happens_before_the_target_gate():
    """Order matters: the gate must come after the inherit attempt, or it refuses first."""
    inherit_at = MAIN.index('target inherited from its checkpoint')
    gate_at = MAIN.index("parser.error('--target is required unless --check-tools is used')")
    assert inherit_at < gate_at, 'the target gate runs before inheritance can happen'


def test_inheritance_is_guarded_by_absence_of_an_operator_target():
    block = MAIN[MAIN.index("if not args.target and getattr(args, 'resume', None):"):]
    block = block[:block.index("parser.error('--target is required")]
    assert 'resumable_snapshot' in block
    assert 'inherited' in block


def test_an_explicit_target_is_never_overridden():
    """The guard is `not args.target`, so an operator value wins by construction."""
    assert "if not args.target and getattr(args, 'resume', None):" in MAIN


def test_a_missing_checkpoint_is_reported_as_a_missing_checkpoint():
    assert 'no resumable checkpoint for that run' in MAIN


def test_no_local_import_shadows_the_module_level_one():
    """A local import in the same function caused UnboundLocalError at the later use."""
    assert 'from src.adaptix.evidence.checkpoint import resumable_snapshot\n        inherited' not in MAIN


def test_the_screen_does_not_block_a_resume_on_a_missing_target():
    screen = (ROOT / 'src' / 'adaptix' / 'ui' / 'screen.py').read_text()
    assert 'if not view.target and not runner.resume_run_id:' in screen
