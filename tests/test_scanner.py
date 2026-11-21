"""Tests for the rule catalogue and configuration scanner (Phase 2/3)."""

from nimbuswatch.aws.mock_data import MockEnvironment
from nimbuswatch.engine import catalog, scanner


def test_rule_catalogue_loads_ten_rules():
    assert len(catalog.get_misconfiguration_rules()) == 10


def test_scanner_detects_seeded_misconfigurations():
    env = MockEnvironment.get_instance()
    env.start()
    env.seed_resources()
    findings = scanner.run_all_scans()
    env.stop()

    assert len(findings) > 0
    failed = {f["rule_id"] for f in findings if f["status"] == "FAIL"}
    assert "NW-AWS-EC2-001" in failed  # open SSH security group
    assert "NW-AWS-RDS-001" in failed  # public RDS instance
