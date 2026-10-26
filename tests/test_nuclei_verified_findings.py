"""Test that Nuclei template matches register as scanner matches (audit D04)."""
import hashlib
import json
from pathlib import Path

import pytest

from src.adaptix.tools import nuclei
from src.adaptix.evidence import verification


def test_nuclei_template_match_is_scanner_matched_row():
    """A positive template match is the scanner's own verdict, labelled scanner_matched."""
    row = {
        'template-id': 'CVE-2021-1234',
        'matched-at': 'http://example.com/vuln',
        'host': 'http://example.com',
        'matcher-name': 'vuln-detected',
        'matcher-status': True,
        'info': {
            'name': 'Test Vulnerability',
            'severity': 'high',
            'tags': ['cve', 'rce']
        },
        'type': 'http'
    }
    
    template_id = 'CVE-2021-1234'
    url = 'http://example.com/vuln'
    severity = 'high'
    evidence_line = 1
    jsonl_ref = '/tmp/test.jsonl'
    jsonl_canon = hashlib.sha256(b'test').hexdigest()
    run_id = 'test-run-001'
    
    template_tags = {template_id: ['cve', 'rce']}
    observation_ids = set()
    observation_tags = {'tech', 'detect', 'favicon'}
    seen_finding_ids = set()
    seen_observation_ids = set()
    findings = []
    observations = []
    
    nuclei._register_nuclei_match(
        row, template_id, url, severity, evidence_line,
        jsonl_ref, jsonl_canon, run_id, template_tags,
        observation_ids, observation_tags,
        seen_finding_ids, seen_observation_ids,
        findings, observations
    )
    
    assert len(findings) == 1
    assert len(observations) == 0
    
    finding = findings[0]
    assert finding['verification_status'] == 'scanner_matched'
    assert finding['verification_method'] == 'nuclei_template_match'
    assert finding['verification_basis'] == 'nuclei_template_match'
    assert finding['independently_verified'] is False
    assert finding['confidence'] == 'scanner_confirmed'
    assert finding['severity'] == 'high'


def test_observation_template_stays_observation():
    """Info/tech templates should stay as observations, not findings."""
    row = {
        'template-id': 'tech-detect',
        'matched-at': 'http://example.com/',
        'host': 'http://example.com',
        'matcher-name': 'nginx',
        'matcher-status': True,
        'info': {
            'name': 'Nginx Detection',
            'severity': 'info',
            'tags': ['tech', 'detect']
        },
        'type': 'http'
    }
    
    template_id = 'tech-detect'
    url = 'http://example.com/'
    severity = 'info'
    evidence_line = 1
    jsonl_ref = '/tmp/test.jsonl'
    jsonl_canon = hashlib.sha256(b'test').hexdigest()
    run_id = 'test-run-002'
    
    template_tags = {template_id: ['tech', 'detect']}
    observation_ids = {template_id}
    observation_tags = {'tech', 'detect'}
    seen_finding_ids = set()
    seen_observation_ids = set()
    findings = []
    observations = []
    
    nuclei._register_nuclei_match(
        row, template_id, url, severity, evidence_line,
        jsonl_ref, jsonl_canon, run_id, template_tags,
        observation_ids, observation_tags,
        seen_finding_ids, seen_observation_ids,
        findings, observations
    )
    
    assert len(findings) == 0
    assert len(observations) == 1
    
    obs = observations[0]
    assert obs['kind'] == 'informational_nuclei_match'


def test_verification_contract_supports_nuclei():
    """The verification module should support nuclei_template_match contract."""
    assert 'nuclei_template_match' in verification.REPLAY_CONTRACTS
    assert 'nuclei_template_match' in verification.CONTRACT_REQUIREMENTS
    assert 'nuclei_template_match' in verification.BASIS_CATEGORIES
    
    contract = verification.REPLAY_CONTRACTS['nuclei_template_match']
    assert contract({'test': 'data'}) == 'confirmed'
    
    requirements = verification.CONTRACT_REQUIREMENTS['nuclei_template_match']
    assert 'template' in requirements.lower()
    assert 'matcher' in requirements.lower()


def test_verified_findings_count_in_report():
    """Older labelled scanner rows still split per provenance in the report."""
    from src.adaptix.reporting.report import final_report
    
    state = {
        'run_id': 'test-report-001',
        'user_prompt': 'test',
        'target': 'http://example.com',
        'hosts': ['example.com'],
        'scope_manifest': {},
        'verified_findings': [
            {
                'finding_id': 'NUC-001',
                'tool_source': 'nuclei',
                'verification_method': 'nuclei_template_match',
                'verification_level': 'verified',
                'verification_status': 'verified',
                'severity': 'high',
                'vulnerability_name': 'Prometheus Metrics - Detect',
                'template_id': 'prometheus-metrics',
                'target': 'http://example.com/metrics'
            },
            {
                'finding_id': 'NUC-002',
                'tool_source': 'nuclei',
                'verification_method': 'nuclei_template_match',
                'verification_level': 'verified',
                'verification_status': 'verified',
                'severity': 'medium',
                'vulnerability_name': 'Package JSON Exposure',
                'template_id': 'package-json',
                'target': 'http://example.com/package.json'
            }
        ],
        'planner_metrics': {'tokens_used': 1000},
        'execution_metrics': {'tool_calls_used': 5},
        'token_ledger': [],
        'errors': [],
        'inconclusive_findings': [],
        'rejected_findings': [],
        'nuclei_observations': [],
        'hypotheses': [],
        'run_started_at': '1700000000.0'
    }
    
    result = final_report(state)
    
    assert result['status'] in ['scan_completed', 'completed_partial']
    metrics = result['report']['metrics']
    
    # Scanner matches are distinguished from independently verified findings
    # (audit D04): the independently verified total stays 0 here.
    total_verified = metrics['finding_classes']['total_verified_findings']
    assert total_verified == 0
    
    nuclei_verified = metrics['finding_classes']['nuclei_verified']
    other_verified = metrics['finding_classes']['other_verified']
    assert nuclei_verified == 2
    assert other_verified == 0
    assert len(result['report']['scanner_matched_findings']) == 2
    assert len(result['report']['independently_verified_findings']) == 0
    assert 'Prometheus Metrics - Detect' in result['markdown_report']


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
