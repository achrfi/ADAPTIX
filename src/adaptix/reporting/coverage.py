"""Separate process success, test coverage, and evidence status in reports.

None of a run's process outcomes (a completed recon, an import, model calls,
HTTP 200s, a clean stop reason) may be read as ``not_vulnerable``. This module
derives, from recorded state only, what was actually executed, whether each
vulnerability class was ever exercised, and why the untested classes were not
tested. Missing coverage states ``not_tested`` with a reason; it never invents
an application-security verdict (audit D01/D02/D05-D09).
"""
from src.adaptix.evidence.verification import INDEPENDENTLY_VERIFIED_METHODS

NOT_TESTED = 'not_tested'
ATTEMPTED = 'attempted'
TESTED = 'tested'

# Tools that exercise a named vulnerability class when they actually execute.
TOOL_CLASSES = {
    'browser_test': ('cross_site_scripting',),
    'idor': ('broken_object_level_authorization',),
    # Deterministic class probes. Each one runs its own check against the observed
    # surface and signs only through a replay contract, so its execution really is
    # an action for that class. Without these entries SQL injection could never be
    # reported as tested: `http_request` carries no class, and the probe was
    # therefore invisible to coverage even while it was proving the class.
    'injection_probe': ('sql_injection', 'nosql_injection'),
    'authorization_probe': ('broken_object_level_authorization',),
    'script_probe': ('cross_site_scripting',),
}

BASE_CLASSES = ('cross_site_scripting', 'sql_injection', 'nosql_injection',
                'broken_object_level_authorization')
# Class labels that describe scanner mechanics or recon artifacts, never a
# vulnerability class an application check could prove.
NON_CLASS_LABELS = {'potential_vulnerability', 'nuclei_template_match',
                    'service_observation', 'service_reachability', '',
                    'none', 'null'}

MEANING = (
    'A zero finding count or a successful process outcome is "not tested", not "not '
    'vulnerable". Coverage is recorded only from actions this run executed; URL '
    'inventories, form observations, route references and AI summaries describe '
    'application surface and do not prove how the application processes input.')


def _executed_actions(state):
    """Attempts whose tool handler returned a recorded outcome (actually ran)."""
    executed = []
    for row in state.get('action_outcomes', []):
        if isinstance(row, dict) and isinstance(row.get('action'), dict):
            executed.append(row['action'])
    return executed


def _discovered_classes(state):
    """Vulnerability classes recorded by candidates, findings and hypotheses."""
    names = set()
    for key in ('candidates', 'verified_findings', 'scanner_matched_findings',
                'inconclusive_findings', 'rejected_findings', 'findings', 'hypotheses'):
        for row in state.get(key, []):
            if not isinstance(row, dict):
                continue
            for field in ('finding_type', 'category'):
                value = row.get(field)
                if isinstance(value, str) and value.lower() not in NON_CLASS_LABELS:
                    names.add(value)
    return sorted(names)


def assessment_coverage(state, stop_reason=None):
    """Recorded activity accounting plus per-class test status, never a verdict.

    Returns process facts (what executed, how many candidates/verifications,
    why the run stopped) and, per class: whether the class was exercised, and
    for untested classes a reason drawn from the run's mode or configuration.
    A count with no recorded backing data is ``None`` ('data unavailable'),
    never 0.
    """
    review_only = bool(state.get('operator_recon_review_only'))
    scanner_disabled = bool(state.get('scanner_disabled'))
    executed = _executed_actions(state)
    by_tool: dict[str, int] = {}
    for action in executed:
        tool = str(action.get('tool') or '?')
        by_tool[tool] = by_tool.get(tool, 0) + 1
    attempted = [row for row in state.get('attempted_actions', []) if isinstance(row, dict)]
    scanner_phase = state.get('nuclei_scan') or {}
    scanner_ran = bool(scanner_phase.get('completed'))
    candidates = state.get('candidates')
    verification_rows = [row for row in state.get('verification_evidence', []) if isinstance(row, dict)]
    browser = state.get('browser_evidence')

    # Independent rows live in the verified_findings bucket (replay/review
    # methods); scanner matches live in scanner_matched_findings, or, for older
    # states, inside verified_findings with the nuclei_template_match method.
    rows = []
    for row in state.get('verified_findings', []):
        if isinstance(row, dict) and row.get('verification_method') not in INDEPENDENTLY_VERIFIED_METHODS:
            continue
        if isinstance(row, dict) and row.get('verification_status') not in ('verified', 'scanner_matched'):
            continue
        rows.append(row)
    scanner_rows = [row for row in state.get('scanner_matched_findings', [])
                    if isinstance(row, dict)]
    legacy_rows = [row for row in state.get('verified_findings', [])
                   if isinstance(row, dict) and row.get('verification_method') == 'nuclei_template_match']
    seen = {row.get('finding_id') for row in scanner_rows}
    scanner_rows += [row for row in legacy_rows if row.get('finding_id') not in seen]

    class_names = sorted(set(BASE_CLASSES) | set(_discovered_classes(state)))
    classes = {}
    for name in class_names:
        class_tools = {tool for tool, mapped in TOOL_CLASSES.items() if name in mapped}
        executed_count = sum(count for tool, count in by_tool.items() if tool in class_tools)
        independent = [row for row in rows
                       if row.get('finding_type') == name or row.get('category') == name]
        scanner = [row for row in scanner_rows
                   if row.get('finding_type') == name or row.get('category') == name]
        if executed_count or independent or scanner:
            status = TESTED if executed_count else ATTEMPTED
            reason = (f'{executed_count} action(s) for this class executed this run'
                      + ('; scanner phase ran' if scanner_ran else ''))
        elif review_only:
            status = NOT_TESTED
            reason = ('operator-import scope is review-only: tool execution, scanner and '
                      'baseline were disabled, so no check of this class ran against a target')
        elif scanner_disabled:
            status = NOT_TESTED
            reason = 'scanner disabled in this run and no class action was executed'
        elif not attempted:
            status = NOT_TESTED
            reason = 'no action was planned and executed in this run'
        else:
            status = NOT_TESTED
            reason = ('this run executed no action for this class; absence of findings here '
                      'is missing coverage, not an application-security result')
        classes[name] = {
            'status': status, 'reason': reason,
            'independently_verified_findings': len(independent) if rows else 0,
            'scanner_matches': len(scanner),
        }
    return {
        'assessment_performed': bool(executed or scanner_ran),
        'review_only': review_only,
        'stop_reason': stop_reason,
        'actions_attempted': len(attempted),
        'actions_executed_by_tool': by_tool,
        'candidates_collected': len(candidates) if candidates is not None else None,
        'verification_records_carried': len(verification_rows),
        'scanner_phase_ran': scanner_ran,
        'browser_observation_pages': (len(browser) if isinstance(browser, list) else None),
        'classes': classes,
        'meaning': MEANING,
        'notes': [
            'The URL inventory, form observation and AI summary describe reachable surface; '
            'they have not proven how the application processes input payloads.',
            'Stop reasons such as budget exhaustion, planning stagnation or review-only mode '
            'describe the run, not application safety.',
        ],
    }
