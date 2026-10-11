import json
from importlib.resources import files

from soc_gpt.attack_mapper import extract_technique_ids, map_rule_techniques
from soc_gpt.sigma_ingestor import load_rules_from_dir


def test_installed_package_includes_real_rules_and_logs():
    root = files('soc_gpt').joinpath('data')
    rules = load_rules_from_dir(root.joinpath('sigma_rules'))
    assert len(rules) == 4
    assert all(rule['es_query']['query']['bool']['must'] for rule in rules)
    assert all(map_rule_techniques(rule) for rule in rules)
    assert json.loads(root.joinpath('sample_logs/auditd_sample.json').read_text())


def test_technique_tags_deduplicate_and_preserve_subtechniques():
    assert extract_technique_ids(['attack.t1548.003', 'attack.T1548.003', 'attack.t1059.004']) == ['T1548.003', 'T1059.004']
