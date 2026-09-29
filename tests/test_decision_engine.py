from remediator.decision_engine import (
    decide,
    determine_decision,
    load_protected_resources,
    load_remediation_rules,
)

def test_low_score_dev_drift_is_auto_fixed():
    drift = {
        "resource": "aws_instance.web",
        "environment": "dev",
        "score": 1,
    }

    result = decide(drift)

    assert result["action"] == "AUTO_FIX"
    assert result["score"] == 1
    assert result["environment"] == "dev"
    assert result["requires_approval"] is False

    assert (
        result["terraform"]["command"]
        == "apply"
    )

    assert (
        result["terraform"]["target"]
        is True
    )

    assert (
        result["terraform"]["auto_approve"]
        is True
    )


def test_low_score_staging_drift_is_auto_fixed():
    drift = {
        "resource": "aws_instance.web",
        "environment": "staging",
        "score": 3,
    }

    result = decide(drift)

    assert result["action"] == "AUTO_FIX"
    assert result["score"] == 3
    assert result["environment"] == "staging"


def test_high_score_is_critical():
    drift = {
        "resource": "aws_security_group.web",
        "environment": "prod",
        "score": 81,
    }

    result = decide(drift)

    assert result["action"] == "CRITICAL"
    assert result["score"] == 81
    assert result["block_deployments"] is True


def test_prod_low_score_cannot_be_auto_fixed():
    drift = {
        "resource": "aws_instance.web",
        "environment": "prod",
        "score": 1,
    }

    result = decide(drift)

    assert result["action"] == "ALERT_ONLY"
    assert result["requires_approval"] is True

    assert (
        "Automatic remediation"
        in result["reason"]
    )


def test_protected_resource_cannot_be_auto_fixed():
    drift = {
        "resource": "aws_s3_bucket.terraform_state",
        "environment": "dev",
        "score": 1,
    }

    result = decide(drift)

    assert result["action"] == "ALERT_ONLY"
    assert result["requires_approval"] is True

    assert (
        "protected"
        in result["reason"].lower()
    )


def test_score_four_is_alert_only():
    drift = {
        "resource": "aws_instance.web",
        "environment": "dev",
        "score": 4,
    }

    result = decide(drift)

    assert result["action"] == "ALERT_ONLY"
    assert result["score"] == 4
    assert result["requires_approval"] is False

    assert (
        result["notifications"]["slack"]
        is True
    )


def test_score_seven_is_alert_only():
    drift = {
        "resource": "aws_instance.web",
        "environment": "dev",
        "score": 7,
    }

    result = decide(drift)

    assert result["action"] == "ALERT_ONLY"
    assert result["score"] == 7


def test_score_eight_is_critical():
    drift = {
        "resource": "aws_instance.web",
        "environment": "prod",
        "score": 8,
    }

    result = decide(drift)

    assert result["action"] == "CRITICAL"
    assert result["score"] == 8
    assert result["requires_approval"] is True
    assert result["block_deployments"] is True

    assert (
        result["notifications"]["slack"]
        is True
    )

    assert (
        result["notifications"]["pagerduty"]
        is True
    )


def test_protected_resource_cannot_be_auto_fixed():
    drift = {
        "resource": "aws_s3_bucket.terraform_state",
        "environment": "dev",
        "score": 1,
    }

    result = decide(drift)

    assert result["action"] == "ALERT_ONLY"
    assert result["requires_approval"] is True

    assert (
        "protected"
        in result["reason"].lower()
    )


def test_protected_resources_are_loaded():
    protected_resources = (
        load_protected_resources()
    )

    assert (
        "aws_s3_bucket.terraform_state"
        in protected_resources
    )

def test_remediation_rules_are_loaded():
    rules = load_remediation_rules()

    assert "remediation" in rules


def test_decision_engine_does_not_modify_drift():
    drift = {
        "resource": "aws_instance.web",
        "environment": "dev",
        "score": 1,
    }

    original_drift = drift.copy()

    decide(drift)

    assert drift == original_drift
