from pathlib import Path
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


def make_audit_result():
    return {
        "bucket": "audit-bucket",
        "key": "audit/test.jsonl",
        "run_id": "test-run",
    }


def make_successful_plan():
    return {
        "command": [
            "terraform",
            "plan",
            "-target=aws_instance.web",
            "-out",
            "test.tfplan",
        ],
        "return_code": 0,
        "stdout": "Plan succeeded",
        "stderr": "",
        "success": True,
    }


def make_successful_show():
    return {
        "command": [
            "terraform",
            "show",
            "-json",
            "test.tfplan",
        ],
        "return_code": 0,
        "stdout": "{}",
        "stderr": "",
        "success": True,
    }


def make_safe_plan_verification():
    return {
        "safe": True,
        "reason": "Plan is safe.",
    }


def make_safe_change_verification():
    return {
        "safe": True,
        "reason": (
            "Terraform plan only affects "
            "the expected resource."
        ),
        "resource": "aws_instance.web",
        "actions": ["update"],
    }


# ============================================================
# AUTO-FIX
# ============================================================


@patch(
    "remediator.remediation_orchestrator.write_audit_record"
)
@patch(
    "remediator.remediation_orchestrator.terraform_plan"
)
@patch(
    "remediator.remediation_orchestrator.create_plan_file"
)
def test_auto_fix_runs_plan(
    mock_create_plan,
    mock_plan,
    mock_audit,
):
    mock_create_plan.return_value = Path(
        "terraform-lab/test.tfplan"
    )

    mock_plan.return_value = make_successful_plan()

    mock_audit.return_value = make_audit_result()

    drift = make_drift(score=1)

    result = process_drift(
        drift,
        audit_bucket="audit-bucket",
    )

    assert result["decision"]["action"] == "AUTO_FIX"
    assert result["plan"]["success"] is True
    assert "apply" not in result

    mock_create_plan.assert_called_once()
    mock_plan.assert_called_once()
    mock_audit.assert_called_once()


@patch(
    "remediator.remediation_orchestrator.write_audit_record"
)
@patch(
    "remediator.remediation_orchestrator.terraform_plan"
)
@patch(
    "remediator.remediation_orchestrator.create_plan_file"
)
def test_auto_fix_does_not_apply_by_default(
    mock_create_plan,
    mock_plan,
    mock_audit,
):
    mock_create_plan.return_value = Path(
        "terraform-lab/test.tfplan"
    )

    mock_plan.return_value = make_successful_plan()

    mock_audit.return_value = make_audit_result()

    drift = make_drift(score=1)

    with patch(
        "remediator.remediation_orchestrator.terraform_apply"
    ) as mock_apply:

        result = process_drift(
            drift,
            audit_bucket="audit-bucket",
        )

    assert result["audit"]
    mock_apply.assert_not_called()


# ============================================================
# ALERT ONLY
# ============================================================


@patch(
    "remediator.remediation_orchestrator.write_audit_record"
)
def test_alert_only_does_not_run_terraform(
    mock_audit,
):
    mock_audit.return_value = make_audit_result()

    drift = make_drift(score=4)

    with patch(
        "remediator.remediation_orchestrator.terraform_plan"
    ) as mock_plan:

        result = process_drift(
            drift,
            audit_bucket="audit-bucket",
        )

    assert result["decision"]["action"] == "ALERT_ONLY"

    mock_plan.assert_not_called()
    mock_audit.assert_called_once()


# ============================================================
# CRITICAL
# ============================================================


@patch(
    "remediator.remediation_orchestrator.write_audit_record"
)
def test_critical_drift_is_blocked(
    mock_audit,
):
    mock_audit.return_value = make_audit_result()

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

    assert result["decision"]["action"] == "CRITICAL"

    assert (
        result["decision"]["block_deployments"]
        is True
    )

    mock_plan.assert_not_called()
    mock_audit.assert_called_once()


# ============================================================
# PLAN FAILURE
# ============================================================


@patch(
    "remediator.remediation_orchestrator.write_audit_record"
)
@patch(
    "remediator.remediation_orchestrator.terraform_plan"
)
@patch(
    "remediator.remediation_orchestrator.create_plan_file"
)
def test_failed_plan_does_not_apply(
    mock_create_plan,
    mock_plan,
    mock_audit,
):
    mock_create_plan.return_value = Path(
        "terraform-lab/test.tfplan"
    )

    mock_plan.return_value = {
        "command": [
            "terraform",
            "plan",
            "-target=aws_instance.web",
            "-out",
            "test.tfplan",
        ],
        "return_code": 1,
        "stdout": "",
        "stderr": "Terraform plan failed",
        "success": False,
    }

    mock_audit.return_value = make_audit_result()

    drift = make_drift(score=1)

    with patch(
        "remediator.remediation_orchestrator.terraform_apply"
    ) as mock_apply:

        result = process_drift(
            drift,
            audit_bucket="audit-bucket",
        )

    assert result["plan"]["success"] is False
    assert "apply" not in result

    mock_apply.assert_not_called()
    mock_audit.assert_called_once()


# ============================================================
# UNSAFE PLAN CHANGES
# ============================================================


@patch(
    "remediator.remediation_orchestrator.write_audit_record"
)
@patch(
    "remediator.remediation_orchestrator.terraform_show_json"
)
@patch(
    "remediator.remediation_orchestrator.terraform_plan"
)
@patch(
    "remediator.remediation_orchestrator.verify_plan_changes"
)
@patch(
    "remediator.remediation_orchestrator.verify_plan_result"
)
@patch(
    "remediator.remediation_orchestrator.create_plan_file"
)
def test_unsafe_plan_changes_are_blocked(
    mock_create_plan,
    mock_verify_result,
    mock_verify_changes,
    mock_plan,
    mock_show_json,
    mock_audit,
):
    mock_create_plan.return_value = Path(
        "terraform-lab/test.tfplan"
    )

    mock_plan.return_value = make_successful_plan()

    mock_verify_result.return_value = (
        make_safe_plan_verification()
    )

    mock_show_json.return_value = (
        make_successful_show()
    )

    mock_verify_changes.return_value = {
        "safe": False,
        "reason": (
            "Terraform plan contains "
            "unexpected resources."
        ),
        "unexpected_resources": [
            "aws_security_group.db"
        ],
    }

    mock_audit.return_value = make_audit_result()

    drift = make_drift(score=1)

    with patch(
        "remediator.remediation_orchestrator.terraform_apply"
    ) as mock_apply:

        result = process_drift(
            drift,
            audit_bucket="audit-bucket",
            execute_apply=True,
        )

    assert (
        result["plan_verification"]["safe"]
        is True
    )

    assert (
        result["change_verification"]["safe"]
        is False
    )

    assert "apply" not in result

    mock_apply.assert_not_called()
    mock_audit.assert_called_once()


# ============================================================
# SUCCESSFUL APPLY + SUCCESSFUL VERIFICATION
# ============================================================


@patch(
    "remediator.remediation_orchestrator.write_audit_record"
)
@patch(
    "remediator.remediation_orchestrator.verify_after_apply"
)
@patch(
    "remediator.remediation_orchestrator.terraform_show_json"
)
@patch(
    "remediator.remediation_orchestrator.terraform_plan"
)
@patch(
    "remediator.remediation_orchestrator.verify_plan_changes"
)
@patch(
    "remediator.remediation_orchestrator.verify_plan_result"
)
@patch(
    "remediator.remediation_orchestrator.create_plan_file"
)
def test_successful_apply_is_verified(
    mock_create_plan,
    mock_verify_result,
    mock_verify_changes,
    mock_plan,
    mock_show_json,
    mock_verify_after_apply,
    mock_audit,
):
    mock_create_plan.return_value = Path(
        "terraform-lab/test.tfplan"
    )

    mock_plan.return_value = make_successful_plan()

    mock_verify_result.return_value = (
        make_safe_plan_verification()
    )

    mock_show_json.return_value = (
        make_successful_show()
    )

    mock_verify_changes.return_value = (
        make_safe_change_verification()
    )

    mock_verify_after_apply.return_value = {
        "resource": "aws_instance.web",
        "drift_resolved": True,
        "differences": {},
    }

    mock_audit.return_value = make_audit_result()

    with patch(
        "remediator.remediation_orchestrator.terraform_apply"
    ) as mock_apply:

        mock_apply.return_value = {
            "command": [
                "terraform",
                "apply",
                "-target=aws_instance.web",
            ],
            "return_code": 0,
            "stdout": "Apply succeeded",
            "stderr": "",
            "success": True,
        }

        drift = make_drift(score=1)

        result = process_drift(
            drift,
            audit_bucket="audit-bucket",
            state_bucket="terraform-state-bucket",
            execute_apply=True,
        )

    assert result["apply"]["success"] is True

    assert (
        result["verification"]["drift_resolved"]
        is True
    )

    assert result["audit"]

    mock_apply.assert_called_once_with(
        resource="aws_instance.web",
        auto_approve=False,
    )

    mock_verify_after_apply.assert_called_once_with(
        resource="aws_instance.web",
        state_bucket="terraform-state-bucket",
        state_key="drift-detector/terraform.tfstate",
    )

    mock_audit.assert_called_once()


# ============================================================
# SUCCESSFUL APPLY + DRIFT STILL EXISTS
# ============================================================


@patch(
    "remediator.remediation_orchestrator.write_audit_record"
)
@patch(
    "remediator.remediation_orchestrator.verify_after_apply"
)
@patch(
    "remediator.remediation_orchestrator.terraform_show_json"
)
@patch(
    "remediator.remediation_orchestrator.terraform_plan"
)
@patch(
    "remediator.remediation_orchestrator.verify_plan_changes"
)
@patch(
    "remediator.remediation_orchestrator.verify_plan_result"
)
@patch(
    "remediator.remediation_orchestrator.create_plan_file"
)
def test_successful_apply_but_drift_remains(
    mock_create_plan,
    mock_verify_result,
    mock_verify_changes,
    mock_plan,
    mock_show_json,
    mock_verify_after_apply,
    mock_audit,
):
    mock_create_plan.return_value = Path(
        "terraform-lab/test.tfplan"
    )

    mock_plan.return_value = make_successful_plan()

    mock_verify_result.return_value = (
        make_safe_plan_verification()
    )

    mock_show_json.return_value = (
        make_successful_show()
    )

    mock_verify_changes.return_value = (
        make_safe_change_verification()
    )

    mock_verify_after_apply.return_value = {
        "resource": "aws_instance.web",
        "drift_resolved": False,
        "differences": {
            "values_changed": {
                (
                    "root['aws_instance.web']"
                    "['attributes']['instance_type']"
                ): {
                    "old_value": "t3.micro",
                    "new_value": "t3.small",
                }
            }
        },
    }

    mock_audit.return_value = make_audit_result()

    with patch(
        "remediator.remediation_orchestrator.terraform_apply"
    ) as mock_apply:

        mock_apply.return_value = {
            "command": [
                "terraform",
                "apply",
                "-target=aws_instance.web",
            ],
            "return_code": 0,
            "stdout": "Apply succeeded",
            "stderr": "",
            "success": True,
        }

        drift = make_drift(score=1)

        result = process_drift(
            drift,
            audit_bucket="audit-bucket",
            state_bucket="terraform-state-bucket",
            execute_apply=True,
        )

    assert result["apply"]["success"] is True

    assert (
        result["verification"]["drift_resolved"]
        is False
    )

    assert result["audit"]

    mock_apply.assert_called_once()

    mock_verify_after_apply.assert_called_once()

    mock_audit.assert_called_once()


# ============================================================
# PLAN VERIFIED BUT APPLY DISABLED
# ============================================================


@patch(
    "remediator.remediation_orchestrator.write_audit_record"
)
@patch(
    "remediator.remediation_orchestrator.terraform_show_json"
)
@patch(
    "remediator.remediation_orchestrator.terraform_plan"
)
@patch(
    "remediator.remediation_orchestrator.verify_plan_changes"
)
@patch(
    "remediator.remediation_orchestrator.verify_plan_result"
)
@patch(
    "remediator.remediation_orchestrator.create_plan_file"
)
def test_verified_plan_does_not_apply_without_execute_flag(
    mock_create_plan,
    mock_verify_result,
    mock_verify_changes,
    mock_plan,
    mock_show_json,
    mock_audit,
):
    mock_create_plan.return_value = Path(
        "terraform-lab/test.tfplan"
    )

    mock_plan.return_value = make_successful_plan()

    mock_verify_result.return_value = (
        make_safe_plan_verification()
    )

    mock_show_json.return_value = (
        make_successful_show()
    )

    mock_verify_changes.return_value = (
        make_safe_change_verification()
    )

    mock_audit.return_value = make_audit_result()

    drift = make_drift(score=1)

    with patch(
        "remediator.remediation_orchestrator.terraform_apply"
    ) as mock_apply:

        result = process_drift(
            drift,
            audit_bucket="audit-bucket",
            state_bucket="terraform-state-bucket",
            execute_apply=False,
        )

    assert result["audit"]

    mock_apply.assert_not_called()


# ============================================================
# APPLY FAILURE
# ============================================================


@patch(
    "remediator.remediation_orchestrator.write_audit_record"
)
@patch(
    "remediator.remediation_orchestrator.terraform_apply"
)
@patch(
    "remediator.remediation_orchestrator.terraform_show_json"
)
@patch(
    "remediator.remediation_orchestrator.terraform_plan"
)
@patch(
    "remediator.remediation_orchestrator.verify_plan_changes"
)
@patch(
    "remediator.remediation_orchestrator.verify_plan_result"
)
@patch(
    "remediator.remediation_orchestrator.create_plan_file"
)
def test_failed_apply_does_not_run_post_verification(
    mock_create_plan,
    mock_verify_result,
    mock_verify_changes,
    mock_plan,
    mock_show_json,
    mock_apply,
    mock_audit,
):
    mock_create_plan.return_value = Path(
        "terraform-lab/test.tfplan"
    )

    mock_plan.return_value = make_successful_plan()

    mock_verify_result.return_value = (
        make_safe_plan_verification()
    )

    mock_show_json.return_value = (
        make_successful_show()
    )

    mock_verify_changes.return_value = (
        make_safe_change_verification()
    )

    mock_apply.return_value = {
        "command": [
            "terraform",
            "apply",
            "-target=aws_instance.web",
        ],
        "return_code": 1,
        "stdout": "",
        "stderr": "Terraform apply failed",
        "success": False,
    }

    mock_audit.return_value = make_audit_result()

    drift = make_drift(score=1)

    with patch(
        "remediator.remediation_orchestrator.verify_after_apply"
    ) as mock_verify_after_apply:

        result = process_drift(
            drift,
            audit_bucket="audit-bucket",
            state_bucket="terraform-state-bucket",
            execute_apply=True,
        )

    assert result["apply"]["success"] is False

    assert "verification" not in result

    mock_verify_after_apply.assert_not_called()

    mock_apply.assert_called_once()

    mock_audit.assert_called_once()


# ============================================================
# MISSING STATE BUCKET
# ============================================================


@patch(
    "remediator.remediation_orchestrator.write_audit_record"
)
@patch(
    "remediator.remediation_orchestrator.terraform_apply"
)
@patch(
    "remediator.remediation_orchestrator.terraform_show_json"
)
@patch(
    "remediator.remediation_orchestrator.terraform_plan"
)
@patch(
    "remediator.remediation_orchestrator.verify_plan_changes"
)
@patch(
    "remediator.remediation_orchestrator.verify_plan_result"
)
@patch(
    "remediator.remediation_orchestrator.create_plan_file"
)
def test_missing_state_bucket_skips_verification(
    mock_create_plan,
    mock_verify_result,
    mock_verify_changes,
    mock_plan,
    mock_show_json,
    mock_apply,
    mock_audit,
):
    mock_create_plan.return_value = Path(
        "terraform-lab/test.tfplan"
    )

    mock_plan.return_value = make_successful_plan()

    mock_verify_result.return_value = (
        make_safe_plan_verification()
    )

    mock_show_json.return_value = (
        make_successful_show()
    )

    mock_verify_changes.return_value = (
        make_safe_change_verification()
    )

    mock_apply.return_value = {
        "command": [
            "terraform",
            "apply",
            "-target=aws_instance.web",
        ],
        "return_code": 0,
        "stdout": "Apply succeeded",
        "stderr": "",
        "success": True,
    }

    mock_audit.return_value = make_audit_result()

    with patch(
        "remediator.remediation_orchestrator.verify_after_apply"
    ) as mock_verify_after_apply:

        result = process_drift(
            drift=make_drift(score=1),
            audit_bucket="audit-bucket",
            state_bucket=None,
            execute_apply=True,
        )

    assert result["apply"]["success"] is True

    assert "verification" not in result

    mock_verify_after_apply.assert_not_called()

    mock_apply.assert_called_once()

    mock_audit.assert_called_once()


# ============================================================
# MULTIPLE DRIFTS
# ============================================================


def test_process_drifts_processes_multiple_drifts():
    drifts = [
        make_drift(score=1),
        make_drift(score=4),
    ]

    with patch(
        "remediator.remediation_orchestrator.process_drift"
    ) as mock_process:

        mock_process.side_effect = [
            {
                "decision": {
                    "action": "AUTO_FIX"
                }
            },
            {
                "decision": {
                    "action": "ALERT_ONLY"
                }
            },
        ]

        from remediator.remediation_orchestrator import (
            process_drifts,
        )

        results = process_drifts(
            drifts,
            audit_bucket="audit-bucket",
        )

    assert len(results) == 2

    assert (
        results[0]["decision"]["action"]
        == "AUTO_FIX"
    )

    assert (
        results[1]["decision"]["action"]
        == "ALERT_ONLY"
    )

    assert mock_process.call_count == 2


if __name__ == "__main__":
    test_successful_apply_but_drift_remains()