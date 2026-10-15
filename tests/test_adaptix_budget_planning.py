import json,time
from types import SimpleNamespace
from src.adaptix.agents.priority import rank_actions,record_outcome,observation_facts
from src.adaptix.agents import planner
from src.adaptix.security.scope import resolve_scope,scope_window,allowed_url
from src.adaptix.workflow.graph import graph
from src.adaptix.tools import registry


def action(tool='httpx',target='http://127.0.0.1',tokens=100,seconds=1,requests=1,value=0.8):
    return {'tool':tool,'target':target,'reason':'test candidate','priority':{
      'goal_relevance':value,'information_gain':value,'evidence_value':value,'confidence':1,
      'estimated_tokens':tokens,'estimated_seconds':seconds,'estimated_requests':requests}}


def budget(tokens=2000,calls=10):
    return {'token_limit':tokens,'tokens':0,'tool_call_limit':calls,'tool_calls':0}


def response(actions,advance=False):
    return SimpleNamespace(usage=SimpleNamespace(total_tokens=130,prompt_tokens=100,completion_tokens=30),
      choices=[SimpleNamespace(message=SimpleNamespace(content=json.dumps({'actions':actions,
      'reflection':'Compare expected evidence and remaining budget','rationale':'utility assessment','advance_scope':advance})))])


def test_equal_utility_prefers_lower_token_cost():
    low=action(tokens=100); high=action(tool='playwright',tokens=900)
    ranked,_=rank_actions({},[high,low],budget())
    assert ranked[0]['tool']=='httpx'
    assert ranked[0]['priority']['score']>ranked[1]['priority']['score']


def test_high_value_evidence_can_outweigh_cheapest_probe():
    reachability=action(tokens=20,value=0.1)
    evidence=action(tool='idor',target='object',tokens=100,requests=2,value=0.95)
    ranked,_=rank_actions({},[reachability,evidence],budget())
    assert ranked[0]['tool']=='idor'


def test_budget_filters_infeasible_candidate_without_static_fallback():
    expensive=action(tokens=5000); affordable=action(tool='playwright',tokens=100)
    ranked,rejected=rank_actions({},[expensive,affordable],budget(tokens=300))
    assert [a['tool'] for a in ranked]==['playwright']
    assert rejected[0]['action']['tool']=='httpx'
    ranked,rejected=rank_actions({},[action(tool='idor')],budget(calls=1))
    assert ranked==[] and rejected


def test_observed_cost_changes_ranking_and_is_reported():
    previous={'http_services':[]}
    outcome={'http_services':[{'url':'http://127.0.0.1','status_code':200}]}
    profiles,feedback=record_outcome(previous,observation_facts(previous),outcome,action(),50)
    assert feedback['new_facts']==1 and profiles['httpx']['mean_seconds']==50
    ranked,_=rank_actions({'tool_profiles':profiles},[action(),action(tool='playwright')],budget())
    assert ranked[0]['tool']=='playwright'
    assert ranked[1]['priority']['effective_seconds']==50


def test_lazy_scope_has_no_16_host_cap_and_ipv6_is_not_materialized():
    scope=resolve_scope(['10.0.0.0/8','2001:db8::/64'],{'blocked_cidrs':[]})
    assert scope['hosts']==[]
    assert len(json.dumps(scope))<1000
    assert scope['total_units']>2**63
    first=scope_window(scope,[],2)
    assert first==['10.0.0.1','10.0.0.2']
    assert scope_window(scope,first,2)==['10.0.0.3','10.0.0.4']
    assert allowed_url('http://10.9.8.7/',[],{80},networks=scope['networks'])
    assert not allowed_url('http://11.0.0.1/',[],{80},networks=scope['networks'])


def test_budget_window_advances_and_report_preserves_unprocessed_scope(monkeypatch):
    catalog={'nmap':{'enabled':True,'path':'cli'}}
    monkeypatch.setattr(planner,'tool_registry',lambda:catalog)
    monkeypatch.setattr(registry,'tool_registry',lambda:catalog)
    windows=[]
    def completion(**kw):
        context=json.loads(kw['messages'][1]['content']); windows.append(context['scope_window'])
        return response([action(tool='nmap',target=context['scope_window'][0])])
    monkeypatch.setattr(planner.litellm,'completion',completion)
    def execute(state):
        host=state['hosts'][0]
        used=state.get('execution_metrics',{}).get('tool_calls_used',0)
        return {'services':[{'host':host,'port':80,'service':'http'}], 'execution_metrics':{'tool_calls_used':used+1}}
    monkeypatch.setattr(registry,'tool_handlers',lambda:{'nmap':execute})
    result=graph.invoke({'target':['127.0.0.0/24'],'tool_call_budget':2,'max_iterations':5},config={'recursion_limit':100})
    assert windows[0]==['127.0.0.1','127.0.0.2']
    assert windows[1]==['127.0.0.2']
    progress=result['report']['scope_progress']
    assert progress['total_target_units']==254 and progress['touched_target_units']==2
    assert progress['untouched_target_units']==252
    assert result['report']['stop_reason']=='budget_exhausted'
    assert len(result['report']['planning_history'])==2


def test_more_than_32_urls_are_valid_and_scope_does_not_expand():
    state={'hosts':['127.0.0.1'],'scope_ports':[80], 'attempted_actions':[
      {'tool':'httpx','target':f'http://127.0.0.1/{i}'} for i in range(40)]}
    assert planner._approved_actions(state,[action(target='http://127.0.0.1/41')],{'httpx'})
    assert not planner._approved_actions(state,[action(target='http://example.com/41')],{'httpx'})


def test_unaffordable_candidates_return_feedback_for_replanning(monkeypatch):
    monkeypatch.setattr(planner,'tool_registry',lambda:{'httpx':{'enabled':True,'path':'cli'}})
    monkeypatch.setattr(planner.litellm,'completion',lambda **kw:response([action(tokens=100000)]))
    result=planner.adaptive_planning({'hosts':['127.0.0.1']})
    assert result['planned_actions']==[] and result['stop_reason'] is None
    assert result['policy_feedback']


def test_expired_time_budget_prevents_model_call(monkeypatch):
    monkeypatch.setattr(planner.litellm,'completion',lambda **kw:(_ for _ in ()).throw(AssertionError('must not call')))
    result=planner.adaptive_planning({'run_started_at':time.time()-10,'time_budget_seconds':1})
    assert result['stop_reason']=='budget_exhausted'


def test_scope_defer_advances_without_claiming_it_was_tested(monkeypatch):
    catalog={'httpx':{'enabled':True,'path':'cli'}}
    monkeypatch.setattr(planner,'tool_registry',lambda:catalog)
    contexts=[]
    def completion(**kw):
        ctx=json.loads(kw['messages'][1]['content']); contexts.append(ctx)
        return response([],advance=len(contexts)==1)
    monkeypatch.setattr(planner.litellm,'completion',completion)
    result=graph.invoke({'target':['127.0.0.0/24'],'tool_call_budget':2,'max_iterations':4},config={'recursion_limit':100})
    assert contexts[0]['scope_window']==['127.0.0.1','127.0.0.2']
    assert contexts[1]['scope_window']==['127.0.0.3','127.0.0.4']
    assert result['report']['scope_progress']['deferred_target_units']==2
    assert result['report']['scope_progress']['touched_target_units']==0
    assert result['report']['status']=='completed_partial'


def test_large_observation_context_is_compacted_without_losing_authoritative_scope(monkeypatch):
    captured={}
    monkeypatch.setattr(planner,'tool_registry',lambda:{'httpx':{'enabled':True,'path':'cli'}})
    monkeypatch.setattr(planner.litellm,'token_counter',lambda **kw:sum(len(m['content']) for m in kw['messages'])//4)
    def completion(**kw):
        captured.update(json.loads(kw['messages'][1]['content']))
        return response([])
    monkeypatch.setattr(planner.litellm,'completion',completion)
    large={'browser_evidence':[{'url':f'http://127.0.0.1/{i}','text_excerpt':'x'*2000} for i in range(30)]}
    result=planner.adaptive_planning({'hosts':['127.0.0.1'],'structured_observations':large})
    assert result['planner_metrics']['removed_context_records']>0
    assert captured['scope_summary']['total_units']==1
    assert len(large['browser_evidence'])==30


def test_selected_urls_on_same_domain_are_separate_lazy_work_units(monkeypatch):
    from src.adaptix.security import scope as core
    monkeypatch.setattr(core.socket,'getaddrinfo',lambda *a,**kw:[(None,None,None,None,('192.0.2.10',0))])
    targets=[f'https://lab.example/item/{i}' for i in range(80)]
    manifest=resolve_scope(targets,{})
    assert manifest['total_units']==80 and len(manifest['units'])==80
    assert scope_window(manifest,[targets[0]],2)==targets[1:3]
    from src.adaptix.security.scope import action_scope_units
    assert action_scope_units(action(target=targets[0]),{},manifest)==[targets[0]]
    assert len(action_scope_units(action(target=targets[0]),{},manifest))!=80
