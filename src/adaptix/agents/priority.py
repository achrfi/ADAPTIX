"""Rank feasible model-generated actions using utility, cost and observed feedback."""
import json
from src.adaptix.workflow.budget import remaining_seconds


def rank_actions(state, actions, budget):
    profiles = state.get('tool_profiles', {})
    left_tokens = budget['token_limit'] - budget['tokens']
    left_calls = budget['tool_call_limit'] - budget['tool_calls']
    left_time = remaining_seconds(state)
    overhead = int(state.get('planner_metrics', {}).get('last_prompt_tokens', 0)) + int(state.get('planner_metrics', {}).get('last_completion_tokens', 0))
    ranked, deferred = [], []
    for action in actions:
        priority = dict(action['priority'])
        profile = profiles.get(action['tool'], {})
        tokens = overhead + max(priority['estimated_tokens'], int(profile.get('mean_context_tokens', 0)))
        seconds = max(priority['estimated_seconds'], float(profile.get('mean_seconds', 0)))
        min_calls = {'idor': 2, 'scenario': 3}.get(action['tool'], 1)
        requests = max(priority['estimated_requests'], min_calls)
        if tokens > left_tokens or seconds > left_time or min_calls > left_calls:
            deferred.append({'action': action, 'reason': 'Estimated cost does not fit remaining token/time/tool-call budget'})
            continue
        benefit = (0.4 * priority['goal_relevance'] + 0.3 * priority['information_gain'] + 0.3 * priority['evidence_value'])
        calibration = 0.25 + 0.75 * float(profile.get('mean_goal_progress', profile.get('productive_fraction', 1)))
        benefit *= priority['confidence'] * calibration
        if benefit <= 0:
            deferred.append({'action': action, 'reason': 'No positive expected utility; propose a useful alternative or stop'})
            continue
        utility_per_token = 1000 * benefit / max(1, tokens)
        pressure = 1 + .25 * seconds / max(.001, left_time) + .15 * requests / max(1, left_calls)
        priority.update(score=round(utility_per_token / pressure, 6), expected_progress_per_1000_tokens=round(utility_per_token, 6), effective_tokens=tokens,
                        effective_seconds=seconds, effective_requests=requests,
                        expected_benefit=round(benefit, 6))
        ranked.append({**action, 'priority': priority})
    ranked.sort(key=lambda a: -a['priority']['score'])
    for rank, action in enumerate(ranked, 1):
        action['priority']['rank'] = rank
    return ranked, deferred


def observation_facts(state):
    fields = ('services', 'http_services', 'candidates', 'browser_evidence', 'idor_findings', 'verification_evidence', 'api_observations', 'scenario_validations', 'web_routes', 'probe_traces')
    facts = set()
    volatile = {'timestamp', 'evidence_id', 'evidence_ref', 'screenshot'}
    for field in fields:
        for item in state.get(field, []):
            stable = {k: v for k, v in item.items() if k not in volatile}
            facts.add(field + ':' + json.dumps(stable, sort_keys=True, default=str))
    return facts


def record_outcome(state, before, result, action, seconds):
    after = {**state, **result}
    new_facts = observation_facts(after) - before
    from src.adaptix.agents.evidence_context import marginal_tokens, evidence_key, FIELDS
    from src.adaptix.agents.progress import progress_assessment
    context_tokens, measurement = marginal_tokens(state, result)
    progress = progress_assessment(state, result)
    profiles = {k: dict(v) for k, v in state.get('tool_profiles', {}).items()}
    old = profiles.get(action['tool'], {})
    count = int(old.get('samples', 0))
    failed = len(result.get('errors', [])) > len(state.get('errors', []))
    productive = progress['goal_progress']
    def mean(key, value): return (float(old.get(key, 0)) * count + value) / (count + 1)
    profiles[action['tool']] = {'samples': count + 1, 'mean_seconds': mean('mean_seconds', seconds),
        'mean_context_tokens': mean('mean_context_tokens', context_tokens),
        'productive_fraction': mean('productive_fraction', productive),
        'mean_goal_progress': mean('mean_goal_progress', productive), 'objective_kind': progress['objective_kind']}
    outcome = {'action': action, 'seconds': round(seconds, 4), 'new_facts': len(new_facts),
               'context_tokens_estimate': context_tokens, 'context_token_measurement': measurement,
               'failed': failed, **progress,
               'new_evidence_keys': [evidence_key(kind, row) for kind in FIELDS for row in result.get(kind, [])
                                     if evidence_key(kind, row) not in {evidence_key(kind, old) for old in state.get(kind, [])}]}
    return profiles, outcome
