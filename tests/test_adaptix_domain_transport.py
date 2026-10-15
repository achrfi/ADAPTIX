import json
import pytest
from pathlib import Path
from src.adaptix.security.transport import bind_url, browser_resolver_rules
from src.adaptix.tools import httpx as ht, nuclei as nt, idor


def state():
    return {'run_id':'domain-transport-test', 'hosts':['192.0.2.22'],
            'scope_aliases':{'lab.example':['192.0.2.22']}, 'scope_ports':[443,9443]}


def test_domain_transport_preserves_host_sni_and_blocks_other_domains():
    actual, headers, sni = bind_url('https://lab.example:9443/api?id=2', state())
    assert actual == 'https://192.0.2.22:9443/api?id=2'
    assert headers == {'Host':'lab.example:9443'}
    assert sni == 'lab.example'
    with pytest.raises(ValueError): bind_url('https://evil.example:9443/', state())
    with pytest.raises(ValueError): bind_url('https://lab.example:9000/', state())


def test_browser_pins_dns_and_denies_other_names():
    assert browser_resolver_rules(state()) == 'MAP lab.example 192.0.2.22, MAP 192.0.2.22 192.0.2.22, MAP * ~NOTFOUND'
    with pytest.raises(ValueError): browser_resolver_rules({**state(), 'scope_aliases':{'lab.example':['192.0.2.99']}})


@pytest.mark.parametrize('module,name,function', [(ht,'httpx',ht.httpx_probe),(nt,'nuclei',nt.nuclei_check)])
def test_cli_adapters_connect_to_pins_and_restore_logical_evidence(monkeypatch,module,name,function):
    monkeypatch.setattr(module,'tool_registry',lambda:{name:{'enabled':True,'path':'/bin/'+name}})
    def run(argv, timeout, stdin):
        assert argv[argv.index('-H')+1] == 'Host: lab.example:9443'
        assert argv[argv.index('-sni')+1] == 'lab.example'
        if name=='httpx':
            assert Path(argv[argv.index('-l')+1]).read_text().strip()=='https://192.0.2.22:9443/api'
            payload={'url':'https://192.0.2.22:9443/api','status_code':200}
        else:
            assert stdin.strip()=='https://192.0.2.22:9443/api'
            payload={'matched-at':'https://192.0.2.22:9443/api','template-id':'adaptix-http-baseline','info':{'severity':'info'}}
        return {'returncode':0,'stdout':json.dumps(payload),'stderr':''}
    monkeypatch.setattr(module,'run_tool',run)
    result=function({**state(),'planned_actions':[{'tool':name,'target':'https://lab.example:9443/api'}]})
    evidence=result['http_services' if name=='httpx' else 'candidates']
    assert evidence[0]['url']=='https://lab.example:9443/api'


def test_idor_connects_to_pin_without_losing_identity_headers(monkeypatch):
    calls=[]
    class Response:
        status_code=200
        text='object-42'
    class Client:
        def __enter__(self): return self
        def __exit__(self,*a): pass
        def request(self,method,url,headers,extensions):
            calls.append((url,headers,extensions)); return Response()
    monkeypatch.setattr(idor.httpx_lib,'Client',lambda **kw:Client())
    scenario={'name':'object','base_url':'https://lab.example:9443','path_template':'/api/{object_id}',
      'object_id':'42','owner_identity':{'name':'a','headers':{'Authorization':'a'}},
      'other_identity':{'name':'b','headers':{'Authorization':'b'}}}
    result=idor.idor_test({**state(),'idor_scenarios':[scenario]})
    assert len(calls)==2
    assert all(url=='https://192.0.2.22:9443/api/42' and headers['Host']=='lab.example:9443' and ext['sni_hostname']=='lab.example' for url,headers,ext in calls)
    assert [headers['Authorization'] for _,headers,_ in calls]==['a','b']
    assert result['idor_findings'][0]['target']=='https://lab.example:9443/api/42'
