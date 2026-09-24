from pathlib import Path

import yaml


BASE_DIR = Path(__file__).resolve().parents[1]


def load_yaml(filename: str):
    path = (
        BASE_DIR
        / "config"
        / filename
    )

    with path.open(
        "r",
        encoding="utf-8",
    ) as file:
        return yaml.safe_load(file)


def test_remediation_rules_exist():
    config = load_yaml(
        "remediation_rules.yaml"
    )

    assert "remediation" in config

    remediation = config["remediation"]

    assert "auto_fix" in remediation
    assert "alert_only" in remediation
    assert "critical" in remediation


def test_auto_fix_policy():
    config = load_yaml(
        "remediation_rules.yaml"
    )

    auto_fix = config[
        "remediation"
    ]["auto_fix"]

    assert auto_fix["enabled"] is True
    assert auto_fix["max_score"] == 3

    assert auto_fix[
        "allowed_environments"
    ] == [
        "dev",
        "staging",
    ]

    assert auto_fix[
        "require_not_protected"
    ] is True


def test_alert_only_policy():
    config = load_yaml(
        "remediation_rules.yaml"
    )

    alert_only = config[
        "remediation"
    ]["alert_only"]

    assert alert_only["min_score"] == 4
    assert alert_only["max_score"] == 7
    assert alert_only[
        "notifications"
    ]["slack"] is True


def test_critical_policy():
    config = load_yaml(
        "remediation_rules.yaml"
    )

    critical = config[
        "remediation"
    ]["critical"]

    assert critical["min_score"] == 8
    assert critical[
        "notifications"
    ]["slack"] is True

    assert critical[
        "notifications"
    ]["pagerduty"] is True

    assert (
        critical["block_deployments"]
        is True
    )


def test_protected_resources_exist():
    config = load_yaml(
        "protected_resources.yaml"
    )

    assert (
        "protected_resources"
        in config
    )

    assert (
        "aws_s3_bucket.terraform_state"
        in config[
            "protected_resources"
        ]
    )