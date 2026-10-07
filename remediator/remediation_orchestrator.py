from __future__ import annotations

from pathlib import Path
from typing import Any

from auditor.audit_logger import (
    create_audit_record,
    write_audit_record,
)
from remediator.decision_engine import (
    decide_remediation,
)
from remediator.plan_verifier import (
    verify_plan_changes,
    verify_plan_result,
)
from remediator.terraform_runner import (
    create_plan_file,
    terraform_apply,
    terraform_plan,
    terraform_show_json,
)
from scanner.aws_scanner import scan_aws_resources
from scanner.state_reader import read_state
from scanner.verification import verify_resource


DEFAULT_STATE_KEY = "drift-detector/terraform.tfstate"


def verify_after_apply(
    *,
    resource: str,
    state_bucket: str,
    state_key: str = DEFAULT_STATE_KEY,
) -> dict[str, Any]:
    """
    Perform a fresh post-apply verification.

    The Terraform state is read again from S3 and the live
    AWS infrastructure is scanned again. The two states are
    then compared to determine whether the original drift
    still exists.
    """

    terraform_state = read_state(
        bucket=state_bucket,
        key=state_key,
    )

    live_state = scan_aws_resources()

    return verify_resource(
        terraform_state=terraform_state,
        live_state=live_state,
        resource=resource,
    )


def _write_audit(
    *,
    resource: str,
    environment: str,
    score: int,
    severity: str,
    action: str,
    reason: str,
    status: str,
    audit_bucket: str | None,
    audit_prefix: str | None,
    terraform_command: list[str] | None = None,
    return_code: int | None = None,
) -> dict[str, Any]:
    """
    Create and persist an audit record.

    Keeping audit creation in one helper prevents the main
    remediation flow from repeating the same code across
    plan, apply, and verification outcomes.
    """

    record = create_audit_record(
        resource=resource,
        environment=environment,
        score=score,
        severity=severity,
        action=action,
        reason=reason,
        status=status,
        terraform_command=terraform_command,
        return_code=return_code,
    )

    return write_audit_record(
        record,
        bucket=audit_bucket,
        prefix=audit_prefix,
    )


def _process_auto_fix(
    drift: dict[str, Any],
    *,
    audit_bucket: str | None,
    audit_prefix: str | None,
    execute_apply: bool,
    state_bucket: str | None,
    state_key: str,
) -> dict[str, Any]:
    """
    Run the safe remediation lifecycle:

    create plan
        ↓
    verify plan command
        ↓
    terraform show -json
        ↓
    verify planned changes
        ↓
    optionally apply
        ↓
    optionally verify live infrastructure
        ↓
    audit
    """

    resource = drift["resource"]
    environment = drift.get(
        "environment",
        "unknown",
    )
    score = int(drift.get("score", 0))
    severity = drift.get(
        "severity",
        "UNKNOWN",
    )

    result: dict[str, Any] = {
        "decision": drift.get(
            "_decision",
            {}
        ),
    }

    # ---------------------------------------------------------
    # 1. Create a unique Terraform plan file
    # ---------------------------------------------------------

    plan_file = create_plan_file()

    result["plan_file"] = str(plan_file)

    # ---------------------------------------------------------
    # 2. Run targeted Terraform plan
    # ---------------------------------------------------------

    plan_result = terraform_plan(
        resource=resource,
        plan_file=str(plan_file),
    )

    result["plan"] = plan_result

    if not plan_result.get("success"):
        result["audit"] = _write_audit(
            resource=resource,
            environment=environment,
            score=score,
            severity=severity,
            action="AUTO_FIX",
            reason=(
                "Terraform plan failed. "
                "Remediation was not applied."
            ),
            status="PLAN_FAILED",
            audit_bucket=audit_bucket,
            audit_prefix=audit_prefix,
            terraform_command=plan_result.get(
                "command"
            ),
            return_code=plan_result.get(
                "return_code"
            ),
        )

        return result

    # ---------------------------------------------------------
    # 3. Verify that the Terraform plan command itself
    #    targeted the expected resource
    # ---------------------------------------------------------

    plan_result_verification = verify_plan_result(
        plan_result=plan_result,
        expected_resource=resource,
    )

    result["plan_verification"] = (
        plan_result_verification
    )

    if not plan_result_verification.get("safe"):
        result["audit"] = _write_audit(
            resource=resource,
            environment=environment,
            score=score,
            severity=severity,
            action="AUTO_FIX",
            reason=(
                plan_result_verification.get(
                    "reason",
                    "Terraform plan verification failed.",
                )
            ),
            status="PLAN_VERIFICATION_FAILED",
            audit_bucket=audit_bucket,
            audit_prefix=audit_prefix,
            terraform_command=plan_result.get(
                "command"
            ),
            return_code=plan_result.get(
                "return_code"
            ),
        )

        return result

    # ---------------------------------------------------------
    # 4. Convert the saved Terraform plan into JSON
    # ---------------------------------------------------------

    show_result = terraform_show_json(
        plan_file=str(plan_file),
    )

    result["show"] = show_result

    if not show_result.get("success"):
        result["audit"] = _write_audit(
            resource=resource,
            environment=environment,
            score=score,
            severity=severity,
            action="AUTO_FIX",
            reason=(
                "Terraform show failed. "
                "The plan could not be inspected safely."
            ),
            status="PLAN_SHOW_FAILED",
            audit_bucket=audit_bucket,
            audit_prefix=audit_prefix,
            terraform_command=show_result.get(
                "command"
            ),
            return_code=show_result.get(
                "return_code"
            ),
        )

        return result

    # ---------------------------------------------------------
    # 5. Verify the actual resources/actions inside
    #    the Terraform plan
    # ---------------------------------------------------------

    plan_json = show_result.get(
        "stdout",
        "",
    )

    try:
        import json

        parsed_plan = json.loads(plan_json)
    except (
        TypeError,
        json.JSONDecodeError,
    ):
        result["change_verification"] = {
            "safe": False,
            "reason": (
                "Terraform plan JSON could not be parsed."
            ),
        }

        result["audit"] = _write_audit(
            resource=resource,
            environment=environment,
            score=score,
            severity=severity,
            action="AUTO_FIX",
            reason=(
                "Terraform plan JSON could not be parsed."
            ),
            status="PLAN_JSON_INVALID",
            audit_bucket=audit_bucket,
            audit_prefix=audit_prefix,
            terraform_command=show_result.get(
                "command"
            ),
            return_code=show_result.get(
                "return_code"
            ),
        )

        return result

    change_verification = verify_plan_changes(
        plan=parsed_plan,
        expected_resource=resource,
    )

    result["change_verification"] = (
        change_verification
    )

    if not change_verification.get("safe"):
        result["audit"] = _write_audit(
            resource=resource,
            environment=environment,
            score=score,
            severity=severity,
            action="AUTO_FIX",
            reason=(
                change_verification.get(
                    "reason",
                    "Terraform plan contains unsafe changes.",
                )
            ),
            status="CHANGE_VERIFICATION_FAILED",
            audit_bucket=audit_bucket,
            audit_prefix=audit_prefix,
            terraform_command=show_result.get(
                "command"
            ),
            return_code=show_result.get(
                "return_code"
            ),
        )

        return result

    # ---------------------------------------------------------
    # 6. Plan is safe.
    #
    #    IMPORTANT:
    #    execute_apply defaults to False.
    #
    #    Therefore simply verifying a safe plan must never
    #    automatically modify infrastructure.
    # ---------------------------------------------------------

    if not execute_apply:
        result["audit"] = _write_audit(
            resource=resource,
            environment=environment,
            score=score,
            severity=severity,
            action="AUTO_FIX",
            reason=(
                "Terraform plan was verified successfully, "
                "but apply execution is disabled."
            ),
            status="PLAN_VERIFIED_APPLY_DISABLED",
            audit_bucket=audit_bucket,
            audit_prefix=audit_prefix,
            terraform_command=plan_result.get(
                "command"
            ),
            return_code=plan_result.get(
                "return_code"
            ),
        )

        return result

    # ---------------------------------------------------------
    # 7. Apply the already-verified Terraform change
    # ---------------------------------------------------------

    apply_result = terraform_apply(
        resource=resource,
        auto_approve=False,
    )

    result["apply"] = apply_result

    # ---------------------------------------------------------
    # 8. NEVER verify live infrastructure after a failed apply
    # ---------------------------------------------------------

    if not apply_result.get("success"):
        result["audit"] = _write_audit(
            resource=resource,
            environment=environment,
            score=score,
            severity=severity,
            action="AUTO_FIX",
            reason=(
                "Terraform apply failed. "
                "Post-apply verification was not performed."
            ),
            status="APPLY_FAILED",
            audit_bucket=audit_bucket,
            audit_prefix=audit_prefix,
            terraform_command=apply_result.get(
                "command"
            ),
            return_code=apply_result.get(
                "return_code"
            ),
        )

        return result

    # ---------------------------------------------------------
    # 9. If no Terraform state bucket was provided, we cannot
    #    perform the fresh state-vs-live verification.
    # ---------------------------------------------------------

    if not state_bucket:
        result["audit"] = _write_audit(
            resource=resource,
            environment=environment,
            score=score,
            severity=severity,
            action="AUTO_FIX",
            reason=(
                "Terraform apply succeeded, but "
                "post-apply verification was skipped "
                "because no Terraform state bucket was provided."
            ),
            status="VERIFICATION_SKIPPED",
            audit_bucket=audit_bucket,
            audit_prefix=audit_prefix,
            terraform_command=apply_result.get(
                "command"
            ),
            return_code=apply_result.get(
                "return_code"
            ),
        )

        return result

    # ---------------------------------------------------------
    # 10. Fresh post-apply verification
    # ---------------------------------------------------------

    verification = verify_after_apply(
        resource=resource,
        state_bucket=state_bucket,
        state_key=state_key,
    )

    result["verification"] = verification

    # ---------------------------------------------------------
    # 11. Determine verification outcome
    # ---------------------------------------------------------

    if verification.get("drift_resolved"):
        verification_status = "VERIFIED"

        verification_reason = (
            "Terraform apply succeeded and "
            "post-apply verification confirmed "
            "that the drift was resolved."
        )
    else:
        verification_status = "VERIFICATION_FAILED"

        verification_reason = (
            "Terraform apply succeeded, but "
            "post-apply verification found that "
            "the drift still exists."
        )

    # ---------------------------------------------------------
    # 12. Audit final remediation state
    # ---------------------------------------------------------

    result["audit"] = _write_audit(
        resource=resource,
        environment=environment,
        score=score,
        severity=severity,
        action="AUTO_FIX",
        reason=verification_reason,
        status=verification_status,
        audit_bucket=audit_bucket,
        audit_prefix=audit_prefix,
        terraform_command=apply_result.get(
            "command"
        ),
        return_code=apply_result.get(
            "return_code"
        ),
    )

    return result


def process_drift(
    drift: dict[str, Any],
    *,
    audit_bucket: str | None = None,
    audit_prefix: str | None = None,
    state_bucket: str | None = None,
    state_key: str = DEFAULT_STATE_KEY,
    execute_apply: bool = False,
) -> dict[str, Any]:
    """
    Process one detected drift.

    Lifecycle:

        Detect
          ↓
        Decide
          ↓
        Plan
          ↓
        Verify plan
          ↓
        Apply
          ↓
        Fresh scan
          ↓
        Verify result
          ↓
        Audit

    execute_apply=False is deliberately the default so that
    running the remediation orchestrator cannot modify
    infrastructure unless execution is explicitly enabled.
    """

    if not isinstance(drift, dict):
        raise ValueError(
            "Drift must be provided as a dictionary."
        )

    resource = drift.get("resource")

    if not resource:
        raise ValueError(
            "Drift must contain a resource."
        )

    score = int(
        drift.get(
            "score",
            0,
        )
    )

    environment = drift.get(
        "environment",
        "unknown",
    )

    severity = drift.get(
        "severity",
        "UNKNOWN",
    )

    # ---------------------------------------------------------
    # 1. Make the remediation decision
    # ---------------------------------------------------------

    decision = decide_remediation(
        drift=drift,
    )

    result: dict[str, Any] = {
        "drift": drift,
        "decision": decision,
    }

    action = decision.get(
        "action"
    )

    # ---------------------------------------------------------
    # 2. ALERT_ONLY
    # ---------------------------------------------------------

    if action == "ALERT_ONLY":
        result["audit"] = _write_audit(
            resource=resource,
            environment=environment,
            score=score,
            severity=severity,
            action=action,
            reason=decision.get(
                "reason",
                "Drift requires notification only.",
            ),
            status="ALERT_ONLY",
            audit_bucket=audit_bucket,
            audit_prefix=audit_prefix,
        )

        return result

    # ---------------------------------------------------------
    # 3. CRITICAL
    # ---------------------------------------------------------

    if action == "CRITICAL":
        result["audit"] = _write_audit(
            resource=resource,
            environment=environment,
            score=score,
            severity=severity,
            action=action,
            reason=decision.get(
                "reason",
                "Critical drift requires deployment blocking.",
            ),
            status="CRITICAL_BLOCKED",
            audit_bucket=audit_bucket,
            audit_prefix=audit_prefix,
        )

        return result

    # ---------------------------------------------------------
    # 4. Any decision other than AUTO_FIX is not allowed
    #    to enter Terraform remediation.
    # ---------------------------------------------------------

    if action != "AUTO_FIX":
        result["audit"] = _write_audit(
            resource=resource,
            environment=environment,
            score=score,
            severity=severity,
            action=str(action),
            reason=decision.get(
                "reason",
                "Remediation action is not supported.",
            ),
            status="REMEDIATION_NOT_EXECUTED",
            audit_bucket=audit_bucket,
            audit_prefix=audit_prefix,
        )

        return result

    # ---------------------------------------------------------
    # 5. AUTO_FIX
    # ---------------------------------------------------------

    auto_fix_drift = dict(drift)
    auto_fix_drift["_decision"] = decision

    auto_fix_result = _process_auto_fix(
        auto_fix_drift,
        audit_bucket=audit_bucket,
        audit_prefix=audit_prefix,
        execute_apply=execute_apply,
        state_bucket=state_bucket,
        state_key=state_key,
    )

    # Preserve the top-level decision and drift.
    auto_fix_result["drift"] = drift
    auto_fix_result["decision"] = decision

    return auto_fix_result


def process_drifts(
    drifts: list[dict[str, Any]],
    *,
    audit_bucket: str | None = None,
    audit_prefix: str | None = None,
    state_bucket: str | None = None,
    state_key: str = DEFAULT_STATE_KEY,
    execute_apply: bool = False,
) -> list[dict[str, Any]]:
    """
    Process multiple drift records independently.
    """

    if not isinstance(drifts, list):
        raise ValueError(
            "Drifts must be provided as a list."
        )

    results: list[dict[str, Any]] = []

    for drift in drifts:
        result = process_drift(
            drift,
            audit_bucket=audit_bucket,
            audit_prefix=audit_prefix,
            state_bucket=state_bucket,
            state_key=state_key,
            execute_apply=execute_apply,
        )

        results.append(result)

    return results
