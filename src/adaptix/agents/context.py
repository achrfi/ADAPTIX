"""Reduce model context without dropping authoritative scope or stored evidence."""
import json


def compact_context(payload, system_prompt, token_budget, count_tokens):
    collections = [payload['services'], payload['known_urls'], payload['attempted_actions'],
                   payload['idor_findings'], payload.get('api_operations', []), payload.get('scenario_candidates', []),
                   payload.get('discovery_targets', []), payload.get('discovery_limitations', []), *payload['observations'].values()]
    removed = 0
    while True:
        encoded = json.dumps(payload, ensure_ascii=False, separators=(',', ':'), default=str)
        if count_tokens(system_prompt, encoded) <= token_budget:
            return encoded, {'removed_context_records': removed, 'context_bytes': len(encoded.encode('utf-8'))}
        # Lists are ordered newest/relevant first. Preserve one current item per kind.
        populated = [values for values in collections if len(values) > 1]
        if populated:
            largest = max(populated, key=lambda values: len(json.dumps(values, default=str)))
            largest.pop()
            removed += 1
            continue
        # Keep durable rejection summaries and credential-free scenario provenance.
        api = payload.get('observations', {}).get('api_observations', [])
        bulky_api = next((row for row in api if len(row.get('records', [])) > 1), None)
        if bulky_api:
            names = set(payload.get('identity_context_summary', {}).get('identities', []))
            bulky_api['records'].sort(key=lambda r: any(r.get(k) in names for k in ('owner', 'user', 'username')), reverse=True)
            bulky_api['records'] = bulky_api['records'][:max(1, len(bulky_api['records']) // 2)]
            removed += 1
            continue
        # Trim lengthy page text/links before discarding current evidence entirely.
        browser = payload.get('observations', {}).get('browser_evidence', [])
        bulky = next((row for row in browser if len(row.get('text_excerpt', '')) > 80 or len(row.get('links', [])) > 1), None)
        if bulky:
            if len(bulky.get('text_excerpt', '')) > 80:
                bulky['text_excerpt'] = bulky['text_excerpt'][:max(80, len(bulky['text_excerpt']) // 2)]
            elif len(bulky.get('links', [])) > 1:
                bulky['links'] = bulky['links'][:max(1, len(bulky['links']) // 2)]
            removed += 1
            continue
        if len(payload['scope_window']) > 1:
            dropped = payload['scope_window'].pop()
            from src.adaptix.security.scope import unit_host
            host = unit_host(dropped)
            if not any(unit_host(u) == host for u in payload['scope_window']):
                payload['domain_aliases'].pop(host, None)
            payload['requested_endpoints'] = [u for u in payload['requested_endpoints'] if u != dropped]
            removed += 1
            continue
        # Preserve the instruction and minimum decision context; stop if they cannot fit.
        return None, {'removed_context_records': removed, 'context_bytes': len(encoded.encode('utf-8'))}
