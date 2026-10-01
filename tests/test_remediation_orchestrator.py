from unittest.mock import patch

from remediator.remediation_orchestrator import (
    process_drift,
)


def make_drift(
    *,
    score: int,
    environment: str = "dev",
    severity: str = "LOW",
) -> dict:
    return {
        "resource": "aws_instance.web",
        "resource_type": "ec2",
        "environment": environment,
        "field": "instance_type",
        "expected": "t3.micro",
        "live": "t3.small",
        "score": score,
        "severity": severity,
    }


@patch(
    "remediator.remediation_orchestrator.write_audit_record"
)
@patch(
    "remediator.remediation_orchestrator.terraform_plan"
)
def test_auto_fix_runs_plan(
    mock_plan,
    mock_audit,
):
    mock_plan.return_value = {
        "command": [
            "terraform",
            "plan",
            "-target=aws_instance.web",
        ],
        "return_code": 0,
        "stdout": "Plan succeeded",
        "stderr": "",
        "success": True,
    }

    mock_audit.return_value = {
        "bucket": "audit-bucket",
        "key": "audit/test.jsonl",
        "run_id": "test-run",
    }

    drift = make_drift(
        score=1
    )

    result = process_drift(
        drift,
        audit_bucket="audit-bucket",
    )

    assert (
        result["decision"]["action"]
        == "AUTO_FIX"
    )

    assert result["plan"]["success"] is True

    assert "apply" not in result

    mock_plan.assert_called_once_with(
        "aws_instance.web"
    )

    mock_audit.assert_called_once()


@patch(
    "remediator.remediation_orchestrator.write_audit_record"
)
@patch(
    "remediator.remediation_orchestrator.terraform_plan"
)
def test_auto_fix_does_not_apply_by_default(
    mock_plan,
    mock_audit,
):
    mock_plan.return_value = {
        "command": [
            "terraform",
            "plan",
            "-target=aws_instance.web",
        ],
        "return_code": 0,
        "stdout": "Plan succeeded",
        "stderr": "",
        "success": True,
    }

    mock_audit.return_value = {
        "bucket": "audit-bucket",
        "key": "audit/test.jsonl",
        "run_id": "test-run",
    }

    drift = make_drift(
        score=1
    )

    with patch(
        "remediator.remediation_orchestrator.terraform_apply"
    ) as mock_apply:

        result = process_drift(
            drift,
            audit_bucket="audit-bucket",
        )

    assert result["audit"]

    assert (
        result["audit"]["bucket"]
        == "audit-bucket"
    )

    mock_apply.assert_not_called()


@patch(
    "remediator.remediation_orchestrator.write_audit_record"
)
def test_alert_only_does_not_run_terraform(
    mock_audit,
):
    mock_audit.return_value = {
        "bucket": "audit-bucket",
        "key": "audit/test.jsonl",
        "run_id": "test-run",
    }

    drift = make_drift(
        score=4
    )

    with patch(
        "remediator.remediation_orchestrator.terraform_plan"
    ) as mock_plan:

        result = process_drift(
            drift,
            audit_bucket="audit-bucket",
        )

    assert (
        result["decision"]["action"]
        == "ALERT_ONLY"
    )

    mock_plan.assert_not_called()
    mock_audit.assert_called_once()


@patch(
    "remediator.remediation_orchestrator.write_audit_record"
)
def test_critical_drift_is_blocked(
    mock_audit,
):
    mock_audit.return_value = {
        "bucket": "audit-bucket",
        "key": "audit/test.jsonl",
        "run_id": "test-run",
    }

    drift = make_drift(
        score=8,
        environment="prod",
        severity="CRITICAL",
    )

    with patch(
        "remediator.remediation_orchestrator.terraform_plan"
    ) as mock_plan:

        result = process_drift(
            drift,
            audit_bucket="audit-bucket",
        )

    assert (
        result["decision"]["action"]
        == "CRITICAL"
    )

    assert (
        result["decision"]["block_deployments"]
        is True
    )

    mock_plan.assert_not_called()
    mock_audit.assert_called_once()


@patch(
    "remediator.remediation_orchestrator.write_audit_record"
)
@patch(
    "remediator.remediation_orchestrator.terraform_plan"
)
def test_failed_plan_does_not_apply(
    mock_plan,
    mock_audit,
):
    mock_plan.return_value = {
        "command": [
            "terraform",
            "plan",
            "-target=aws_instance.web",
        ],
        "return_code": 1,
        "stdout": "",
        "stderr": "Terraform plan failed",
        "success": False,
    }

    mock_audit.return_value = {
        "bucket": "audit-bucket",
        "key": "audit/test.jsonl",
        "run_id": "test-run",
    }

    drift = make_drift(
        score=1
    )

    with patch(
        "remediator.remediation_orchestrator.terraform_apply"
    ) as mock_apply:

        result = process_drift(
            drift,
            audit_bucket="audit-bucket",
        )

    assert (
        result["plan"]["success"]
        is False
    )

    assert "apply" not in result

    mock_apply.assert_not_called()

    mock_audit.assert_called_once()