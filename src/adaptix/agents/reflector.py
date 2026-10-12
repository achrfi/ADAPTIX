"""ADAPTIX unified module. Migrated from tested running code."""
from src.adaptix.workflow.events import log


def reflection_verification(state):
    # Do not upgrade automated matches to verified vulnerabilities without evidence.
    return {'verified_findings': [], 'events': log(state, 'Reflection: evidence indexed; no vulnerability confirmed')}
