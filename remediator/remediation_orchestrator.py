from typing import Any

from auditor.audit_logger import (
    create_audit_record,
    write_audit_record,
)
from remediator.decision_engine import decide
from remediator.terraform_runner import (
    terraform_apply,
    terraform_plan,
)


def process_drift(
    drift: dict[str, Any],
    *,
    audit_bucket: str | None = None,
    audit_prefix: str | None = None,
    execute_apply: bool = False,
) -> dict[str, Any]:
    """
    Process one scored drift through the remediation policy.

    Flow:

        scored drift
            ↓
        decision engine
            ↓
        plan / alert / critical
            ↓
        audit record

    Terraform apply is disabled by default.
    """

    decision = decide(drift)

    resource = decision["resource"]
    action = decision["action"]

    result: dict[str, Any] = {
        "decision": decision,
    }

    # ---------------------------------------------------------
    # ALERT ONLY
    # ---------------------------------------------------------

    if action == "ALERT_ONLY":
        audit_record = create_audit_record(
            resource=resource,
            environment=decision["environment"],
            score=decision["score"],
            severity=drift.get(
                "severity",
                "UNKNOWN",
            ),
            action=action,
            reason=decision["reason"],
            status="ALERTED",
        )

        audit_result = write_audit_record(
            audit_record,
            bucket=audit_bucket,
            prefix=audit_prefix,
        )

        result["audit"] = audit_result

        return result

    # ---------------------------------------------------------
    # CRITICAL
    # ---------------------------------------------------------

    if action == "CRITICAL":
        audit_record = create_audit_record(
            resource=resource,
            environment=decision["environment"],
            score=decision["score"],
            severity=drift.get(
                "severity",
                "CRITICAL",
            ),
            action=action,
            reason=decision["reason"],
            status="BLOCKED",
        )

        audit_result = write_audit_record(
            audit_record,
            bucket=audit_bucket,
            prefix=audit_prefix,
        )

        result["audit"] = audit_result

        return result

    # ---------------------------------------------------------
    # AUTO FIX
    # ---------------------------------------------------------

    if action != "AUTO_FIX":
        raise ValueError(
            f"Unsupported remediation action: {action}"
        )

    # ---------------------------------------------------------
    # PLAN
    # ---------------------------------------------------------

    plan_result = terraform_plan(
        resource
    )

    result["plan"] = plan_result

    if not plan_result["success"]:
        audit_record = create_audit_record(
            resource=resource,
            environment=decision["environment"],
            score=decision["score"],
            severity=drift.get(
                "severity",
                "UNKNOWN",
            ),
            action=action,
            reason=(
                "Terraform plan failed. "
                "Apply was not attempted."
            ),
            status="PLAN_FAILED",
            terraform_command=plan_result[
                "command"
            ],
            return_code=plan_result[
                "return_code"
            ],
        )

        audit_result = write_audit_record(
            audit_record,
            bucket=audit_bucket,
            prefix=audit_prefix,
        )

        result["audit"] = audit_result

        return result

    # ---------------------------------------------------------
    # PLAN SUCCEEDED — WAIT FOR EXPLICIT APPLY
    # ---------------------------------------------------------

    if not execute_apply:
        audit_record = create_audit_record(
            resource=resource,
            environment=decision["environment"],
            score=decision["score"],
            severity=drift.get(
                "severity",
                "UNKNOWN",
            ),
            action=action,
            reason=(
                "Terraform plan succeeded, but "
                "automatic apply is disabled."
            ),
            status="PLAN_ONLY",
            terraform_command=plan_result[
                "command"
            ],
            return_code=plan_result[
                "return_code"
            ],
        )

        audit_result = write_audit_record(
            audit_record,
            bucket=audit_bucket,
            prefix=audit_prefix,
        )

        result["audit"] = audit_result

        return result

    # ---------------------------------------------------------
    # APPLY
    # ---------------------------------------------------------

    terraform_config = decision.get(
        "terraform",
        {},
    )

    auto_approve = bool(
        terraform_config.get(
            "auto_approve",
            False,
        )
    )

    apply_result = terraform_apply(
        resource=resource,
        auto_approve=auto_approve,
    )

    result["apply"] = apply_result

    status = (
        "SUCCESS"
        if apply_result["success"]
        else "APPLY_FAILED"
    )

    audit_record = create_audit_record(
        resource=resource,
        environment=decision["environment"],
        score=decision["score"],
        severity=drift.get(
            "severity",
            "UNKNOWN",
        ),
        action=action,
        reason=decision["reason"],
        status=status,
        terraform_command=apply_result[
            "command"
        ],
        return_code=apply_result[
            "return_code"
        ],
    )

    audit_result = write_audit_record(
        audit_record,
        bucket=audit_bucket,
        prefix=audit_prefix,
    )

    result["audit"] = audit_result

    return result


def process_drifts(
    scored_drifts: list[dict[str, Any]],
    *,
    audit_bucket: str | None = None,
    audit_prefix: str | None = None,
    execute_apply: bool = False,
) -> list[dict[str, Any]]:
    """
    Process all detected drifts.
    """

    results = []

    for drift in scored_drifts:
        result = process_drift(
            drift,
            audit_bucket=audit_bucket,
            audit_prefix=audit_prefix,
            execute_apply=execute_apply,
        )

        results.append(result)

    return results