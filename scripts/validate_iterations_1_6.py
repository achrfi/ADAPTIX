"""Run actual adapters on a disposable lab; optional real model, no external target."""
import argparse
import hashlib
import json
import os
import subprocess
import time
from pathlib import Path
from unittest.mock import patch
from types import SimpleNamespace

os.environ.setdefault('LITELLM_LOCAL_MODEL_COST_MAP', 'True')
from lab.api_fixture import FixtureLab, ACCOUNTS, OBJECT
from src.adaptix.workflow.graph import graph
from src.adaptix.workflow.nodes import scope_guard
from src.adaptix.tools.registry import tool_registry
from src.adaptix.tools.httpx import httpx_probe
from src.adaptix.tools.nuclei import nuclei_check
from src.adaptix.tools.playwright import browser_observe
from src.adaptix.tools.idor import idor_test
from src.adaptix.agents.planner import adaptive_planning
from src.adaptix.agents.priority import observation_facts, record_outcome
from src.adaptix.processing.observations import observation_processing
from src.adaptix.agents.reflector import reflection_verification
from src.adaptix.reporting.report import final_report
from src.adaptix.evidence.audit import write_json, inspect_bundle
from src.adaptix.evidence.verification import write_verification_record
from src.adaptix.security.authorization import _key
from src.adaptix.config import ROOT


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--live-model', action='store_true')
    p.add_argument('--model', default='ollama_chat/qwen3:14b')
    args = p.parse_args()
    run_id = 'acceptance-i1-i6-' + str(int(time.time()))
    summary = {'run_id': run_id, 'checks': {}, 'live_model_requested': args.live_model}
    with FixtureLab() as lab:
        state = {'run_id': run_id, 'target': [lab.url], 'tool_call_budget': 20, 'max_iterations': 10,
                 'token_budget': 30000, 'time_budget_seconds': 600, 'events': [], 'errors': [],
                 'lab_manifest': lab.manifest(), 'llm_model': args.model}
        state.update(scope_guard(state))
        assert state['status'] == 'scope_ok'
        state['scope_ports'] = [lab.server.server_address[1]]
        catalog = tool_registry(); state['tool_catalog'] = catalog
        assert all(catalog[n].get('path') for n in ('httpx', 'nuclei', 'playwright'))
        assert catalog['nmap']['enabled'] is False and catalog['nmap']['path'] is None
        def record_adapter(name, adapter, target, scenarios=None):
            previous = {**state, 'planned_actions': [{'tool': name, 'target': target}], 'action_cursor': 0}
            if scenarios is not None:
                previous['idor_scenarios'] = scenarios
                previous.pop('idor_findings', None)
            action = previous['planned_actions'][0]
            started = time.monotonic()
            result = adapter(previous)
            profiles, outcome = record_outcome(previous, observation_facts(previous), result, action, time.monotonic() - started)
            state.update(result)
            state['tool_profiles'] = profiles
            state.setdefault('action_outcomes', []).append(outcome)
            state.setdefault('attempted_actions', []).append(action)
            return result
        for name, adapter in [('httpx', httpx_probe), ('nuclei', nuclei_check), ('playwright', browser_observe)]:
            state['planned_actions'] = [{'tool': name, 'target': lab.url}]
            state['action_cursor'] = 0
            print('LIVE ADAPTER', name, flush=True)
            record_adapter(name, adapter, lab.url)
        assert not state['errors'], state['errors']
        assert state['http_services'] and state['browser_evidence']
        assert state.get('nuclei_template_selections'), 'Selection/policy audit required, even when no template matches'
        assert all(row['execution_status'] in ('completed', 'no_matching_templates') for row in state['nuclei_template_selections'])
        observed = record_adapter('playwright', browser_observe, lab.url + '/readonly-policy-check')
        assert not observed['errors'], observed['errors']
        assert any(r['method'] == 'POST' for r in observed['browser_evidence'][-1]['blocked_requests'])
        assert not any(h['method'] == 'POST' and h['path'] == '/should-not-write' for h in lab.hits)
        summary['checks']['browser_read_only_gate'] = {'passed': True, 'post_blocked': True}
        state.update(observation_processing(state)); state.update(reflection_verification(state))
        assert state['metrics']['raw_bytes'] > 0 and state['metrics']['structured_bytes'] > 0
        assert not state['verified_findings']
        if any(x.get('template_id') == 'adaptix-http-baseline' for x in state.get('candidates', [])):
            assert state['rejected_findings']
        summary['checks']['recon_and_multi_tool_processing'] = {'passed': True, 'metrics': state['metrics']}
        import httpx
        with httpx.Client(trust_env=False) as client:
            for role, credential in ACCOUNTS.items():
                response = client.get(lab.url + '/whoami', headers={'Authorization': credential})
                assert response.status_code == 200 and response.json()['identity'] == role
        cases = {}
        for mode, expected in [('vulnerable', 'verified'), ('protected', 'rejected'), ('public', 'inconclusive')]:
            result = record_adapter('idor', idor_test, mode + '-order', [lab.scenario(mode)])
            finding = result['idor_findings'][0]
            assert finding['verification_status'] == expected
            assert finding['requests'] and finding['responses'] and finding['response_diff']
            cases[mode] = finding
        state['idor_findings'] = list(cases.values())
        _key(create=True)
        for mode in ('vulnerable', 'protected'):
            finding = cases[mode]
            proof = write_verification_record(state, {**finding, 'template_id': 'lab-private-object-access',
                'url': finding['target'], 'verification_method': 'deterministic_replay', 'verification_basis': 'private_object_access'})
            state.setdefault('verification_evidence', []).append(proof)
            state.setdefault('candidates', []).append({'template_id': proof['template_id'], 'url': proof['url'],
                                       'severity': 'high', 'source_tool': 'idor_replay'})
        state.update(reflection_verification(state))
        assert len(state['verified_findings']) == 1
        assert any(x.get('source_tool') == 'idor_test' for x in state['verified_findings'])
        assert any(x.get('scenario') == 'public-order' for x in state['inconclusive_findings'])
        assert any(x['verification_evidence'] and x['verification_evidence']['result'] == 'refuted' for x in state['rejected_findings'])
        summary['checks']['signed_replay_verification'] = {'passed': True, 'verified': 1, 'refuted': 1}
        state.update(observation_processing(state))
        summary['checks']['idor_actual_lab'] = {'passed': True, 'cases': {k: v['verification_status'] for k, v in cases.items()}}
        # Mock foundation: two observation-driven graph turns, no fixed production pipeline.
        catalog_stub = {'httpx': {'enabled': True, 'path': 'mock', 'risk': 'observe'}}
        contexts = []
        def completion(**kw):
            context = json.loads(kw['messages'][1]['content']); contexts.append(context)
            target = lab.url + ('/whoami' if context['observations']['http_services'] else '/')
            action = {'tool': 'httpx', 'target': target, 'reason': 'Respond to current observations',
                      'priority': {'goal_relevance': 1, 'information_gain': 1, 'evidence_value': 0.8, 'confidence': 1,
                                   'estimated_tokens': 10, 'estimated_seconds': 0.1, 'estimated_requests': 1}}
            return SimpleNamespace(usage=SimpleNamespace(prompt_tokens=100, completion_tokens=30, total_tokens=130),
                                   choices=[SimpleNamespace(message=SimpleNamespace(content=json.dumps({'actions': [action],
                                   'rationale': 'Based on current observation', 'reflection': 'Review remaining uncertainty before next observation'})))])
        def observe(s):
            return {'http_services': s.get('http_services', []) + [{'url': s['planned_actions'][0]['target'], 'status_code': 200}],
                    'execution_metrics': {'tool_calls_used': s.get('execution_metrics', {}).get('tool_calls_used', 0) + 1}}
        with patch('src.adaptix.agents.planner.tool_registry', return_value=catalog_stub), patch('src.adaptix.tools.registry.tool_registry', return_value=catalog_stub), patch('src.adaptix.tools.registry.tool_handlers', return_value={'httpx': observe}), patch('src.adaptix.agents.decisions.litellm.completion', side_effect=completion), patch('src.adaptix.agents.planner.litellm.token_counter', return_value=100):
            mock = graph.invoke({'run_id': run_id + '-mock', 'target': [lab.url], 'max_iterations': 2, 'tool_call_budget': 5,
                                 'token_budget': 10000, 'user_prompt': 'Observe the lab and review remaining uncertainty'}, config={'recursion_limit': 50})
            assert mock['iterations'] == 2 and len(mock['attempted_actions']) == 2
            assert contexts[0]['observations'] != contexts[1]['observations']
            write_json(state, 'mock-run', mock)
            # Negative scope path must never reach provider or tool.
            blocked = graph.invoke({'target': ['0.0.0.0'], 'run_id': run_id + '-blocked'})
            assert blocked['status'] == 'scope_blocked'
        summary['checks']['mock_two_turns_and_scope_block'] = {'passed': True, 'iterations': mock['iterations']}
        if args.live_model:
            summary['live_model_runs'] = []
            if args.model.startswith(('ollama/', 'ollama_chat/')):
                base = os.getenv('ADAPTIX_OLLAMA_BASE_URL', 'http://127.0.0.1:11434')
                model_name = args.model.split('/', 1)[1]
                with httpx.Client(trust_env=False, timeout=20) as model_client:
                    tags = model_client.get(base + '/api/tags').json().get('models', [])
                    summary['model_info'] = next((m for m in tags if m.get('name') == model_name), {'name': model_name})
                    show = model_client.post(base + '/api/show', json={'model': model_name}).json()
                    summary['model_info']['parameters'] = show.get('parameters', 'provider_default')
                    summary['model_info']['ollama_version'] = model_client.get(base + '/api/version').json().get('version')
            for mode, expected in [('vulnerable', 'verified'), ('protected', 'rejected')]:
                print('LIVE MODEL', mode, flush=True)
                prompt = f'Uji kontrol akses objek lab memakai skenario {mode}-order yang disediakan. Gunakan pengujian IDOR dua identitas, evaluasi hasilnya, lalu berhenti. Jangan melakukan pemindaian lain.'
                initial = {'run_id': run_id + '-llm-' + mode, 'target': [lab.url + '/' + mode + '/orders/42'], 'user_prompt': prompt,
                           'idor_scenarios': [lab.scenario(mode)], 'lab_manifest': lab.manifest(), 'llm_model': args.model,
                           'planner_retry_limit': 1, 'max_iterations': 6, 'tool_call_budget': 4, 'token_budget': 30000,
                           'time_budget_seconds': 240, 'events': [], 'errors': []}
                result = graph.invoke(initial, config={'recursion_limit': 100})
                assert not result.get('errors'), result.get('errors')
                assert result['report']['stop_reason'] == 'no_new_actions', result['report']['stop_reason']
                assert result['report']['status'] == 'scan_completed', result['report']['status']
                assert result['planner_metrics']['mode'] == 'llm'
                assert result.get('idor_findings') and result['idor_findings'][0]['verification_status'] == expected
                group = 'verified_findings' if expected == 'verified' else 'rejected_findings'
                assert len(result['report'][group]) == 1
                assert result['report'][group][0]['source_tool'] == 'idor_test'
                assert all(a['tool'] == 'idor' for a in result['attempted_actions'])
                assert len(result['attempted_actions']) == 1
                assert len(result['reflection_history']) >= 2
                assert all(item['reflection'] for item in result['reflection_history'])
                assert sum(e['tokens_charged'] for e in result['token_ledger']) == result['planner_metrics']['tokens_used']
                integrity = inspect_bundle(result['artifact_bundle']['evidence-index'])
                assert integrity['status'] == 'integrity_verified'
                summary['live_model_runs'].append({'case': mode, 'status': result['report']['status'],
                    'finding': expected, 'actions': result['attempted_actions'], 'tokens': result['planner_metrics']['tokens_used'],
                    'stop_reason': result['report']['stop_reason'], 'bundle': result['artifact_bundle'], 'integrity': integrity['status']})
        assert lab.object == OBJECT
        lab.reset(); assert lab.object == OBJECT
        summary['checks']['reset_and_cleanup'] = {'passed': True, 'state_unchanged': True}
        state.update(final_report(state))
        summary['bundle'] = state['artifact_bundle']
        summary['integrity'] = inspect_bundle(state['artifact_bundle']['evidence-index'])['status']
        summary['lab_manifest'] = lab.manifest()
        summary['lab_hits'] = lab.hits
    summary['lab_listener_closed'] = True
    import socket
    with socket.socket() as listener_check:
        listener_check.settimeout(1)
        assert listener_check.connect_ex(('127.0.0.1', lab.server.server_address[1])) != 0
    summary['status'] = 'passed'
    summary_path = write_json({'run_id': run_id + '-summary'}, 'acceptance-summary', summary)
    print('SUMMARY', str(summary_path), flush=True)
    print(json.dumps(summary, ensure_ascii=False), flush=True)


if __name__ == '__main__':
    main()
