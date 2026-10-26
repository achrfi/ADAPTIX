"""Ground model reflection in stored evidence before an action/stop is accepted."""
from src.adaptix.agents.evidence_context import evidence_key, FIELDS
from src.adaptix.agents.progress import objective_kind


def grounded_review(state, decision):
    from src.adaptix.agents.reflector import collect_findings
    findings = collect_findings(state)
    kind = objective_kind(state)
    rows = [(name, row) for name in FIELDS for row in state.get(name, [])]
    valid_refs = {evidence_key(name, row) for name, row in rows}
    valid_refs.update(row.get('url') or row.get('target') for _, row in rows)
    # A sealed verification record is the strongest evidence a run holds, and the
    # planner is shown its path so it can escalate on a proven finding. That path must
    # therefore be citable: without it here, a review that correctly names the artifact
    # was rejected as "evidence not present", and the run stopped on its own best proof.
    valid_refs.update(record.get('evidence_ref')
                      for record in state.get('verification_evidence') or []
                      if isinstance(record, dict) and record.get('evidence_ref'))
    valid_refs.discard(None)
    errors = state.get('errors', [])
    answered = findings['verified_findings'] + [x for x in findings['rejected_findings'] if x.get('verification_evidence')]
    complete = bool(answered) if kind == 'authorization' else False
    if kind == 'authorization' and state.get('idor_scenarios'):
        required = {row['name'] for row in state['idor_scenarios']}
        named = {name for name in required if name in state.get('user_prompt', '')}
        required = named or required
        complete = complete and required.issubset({row.get('scenario') for row in answered})
    if kind == 'service_observation':
        title_needed = any(word in state.get('user_prompt', '').lower() for word in ('judul', 'title'))
        http = state.get('http_services', []) + state.get('browser_evidence', [])
        complete = bool(http) and all(isinstance(row.get('status_code'), int) and (not title_needed or row.get('title')) for row in http)
        manifest = state.get('scope_manifest', {})
        complete = complete and len(state.get('scope_touched', [])) >= manifest.get('total_units', 1)
    if kind == 'navigation':
        pages = state.get('browser_evidence', [])
        complete = any(destination.get('url') != source.get('url') and destination.get('url') in source.get('links', []) and destination.get('title')
                       for index, source in enumerate(pages) for destination in pages[index + 1:])
    status = 'achieved' if complete else 'blocked' if errors else 'uncertain' if findings['inconclusive_findings'] else 'in_progress'
    model = decision.review.model_dump() if decision.review else None
    feedback = []
    if model:
        invalid = [ref for ref in model['evidence_refs'] if ref not in valid_refs]
        if invalid:
            feedback.append('Reflection cites evidence that is not present in the current scope/context')
        if model['goal_status'] == 'achieved' and (not model['evidence_refs'] or not complete):
            feedback.append('Goal achievement is not established by stored objective-specific evidence')
            if kind == 'navigation' and not complete:
                feedback.append('A discovered link is not a visited page. Open a distinct in-scope URL actually listed in the observed source links, then inspect its destination title. Only source-page evidence exists until that tool returns.')
            elif kind == 'authorization' and not complete:
                feedback.append('Authorization needs an authenticated decisive proof for every requested scenario; untested or invalid-identity scenarios remain unresolved.')
            elif kind == 'service_observation' and not complete:
                feedback.append('Collect the requested HTTP status/title for every requested target unit; seed URLs and unvisited links are not observations.')
        if model['goal_status'] == 'achieved' and decision.actions:
            feedback.append('Do not schedule further tools after declaring the objective achieved')
    current = state.get('recent_evidence_keys', [])
    assessment = {'objective_kind': kind, 'goal_status': status,
                  'evidence_refs': [ref for ref in current if ref in valid_refs] or list(sorted(ref for ref in valid_refs if isinstance(ref, str) and ':' in ref))[:4],
                  'uncertainty': [row['target'] for row in findings['inconclusive_findings']],
                  'failure': errors[-3:], 'decision_change': decision.reflection,
                  'model_review': model, 'origin': 'model_and_evidence' if model else 'legacy_text_grounded_by_controller',
                  'validation_errors': feedback}
    return assessment, feedback
