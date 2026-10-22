"""Scanner candidates and the provider-retry floor: new Task 1/6 guarantees."""
import pytest

from src.adaptix.agents.hypotheses import evidence_hypotheses
from src.adaptix.agents import decisions


def test_nuclei_candidates_seed_classified_hypotheses_with_provenance():
    """An sqli/xss scanner match becomes a grounded, unverified hypothesis seed."""
    state = {'probe_traces': [],
             'candidates': [
                 {'template_id': 'sqli-postgresql-pg_sleep', 'url': 'http://lab.example/sql',
                  'finding_type': 'potential_vulnerability', 'severity': 'high'},
                 {'template_id': 'xss-reflected-script-tag', 'url': 'http://lab.example/search',
                  'finding_type': 'potential_vulnerability', 'severity': 'medium'},
                 {'template_id': 'CVE-2022-22947', 'url': 'http://lab.example/actuator',
                  'finding_type': 'potential_vulnerability', 'severity': 'critical'},
                 {'template_id': 'tech-detect', 'url': 'http://lab.example/',
                  'finding_type': 'service_reachability', 'severity': 'info'}]}
    refs = {'candidates:x' + '0' * 15}
    derived = evidence_hypotheses(state)
    by_cat = {row['category']: row for row in derived}
    assert by_cat['sql_injection']['target'] == 'http://lab.example/sql'
    assert by_cat['cross_site_scripting']['target'] == 'http://lab.example/search'
    # CVE identifiers and technology rows never become fabricated hypotheses
    assert 'known_cve' not in by_cat and not any('tech' in r['category'] for r in derived)
    sql = by_cat['sql_injection']
    assert 'Unverified scanner match' in sql['rationale']
    assert sql['evidence_refs']


def test_scanner_seeds_respect_the_valid_ref_whitelist():
    state = {'probe_traces': [],
             'candidates': [{'template_id': 'sqli-basic-error', 'url': 'http://lab.example/s'}]}
    derived = evidence_hypotheses(state, valid_refs=set())
    assert not derived  # wholly unverifiable provenance is dropped, not recorded


def test_schema_retry_never_falls_below_the_viable_output_floor():
    """A length-limited native-schema decision retries at the schema's floor, not 160."""
    previous = 850
    schema_floor = decisions.MIN_VIABLE_OUTPUT
    assert max(schema_floor, int(previous * decisions.ENVELOPE_SHRINK)) == schema_floor
    plain = max(decisions.MIN_RETRY_OUTPUT, int(previous * decisions.ENVELOPE_SHRINK))
    assert plain < schema_floor  # calm freeform retries still may shrink further
