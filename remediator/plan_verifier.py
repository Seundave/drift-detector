import json
from typing import Any


ALLOWED_ACTIONS = {
    "create",
    "update",
}


def parse_plan_json(
    plan_json: str,
) -> dict[str, Any]:
    """
    Parse Terraform's JSON plan output.
    """

    if not plan_json:
        raise ValueError(
            "Terraform plan JSON is empty."
        )

    try:
        parsed = json.loads(
            plan_json
        )
    except json.JSONDecodeError as exc:
        raise ValueError(
            "Terraform plan output is not valid JSON."
        ) from exc

    if not isinstance(parsed, dict):
        raise ValueError(
            "Terraform plan JSON must be an object."
        )

    return parsed


def get_planned_changes(
    plan: dict[str, Any],
) -> list[dict[str, Any]]:
    """
    Extract resource changes from a Terraform
    JSON plan.
    """

    resource_changes = plan.get(
        "resource_changes",
        [],
    )

    if not isinstance(
        resource_changes,
        list,
    ):
        raise ValueError(
            "Terraform resource_changes must be a list."
        )

    return resource_changes


def get_change_addresses(
    plan: dict[str, Any],
) -> list[str]:
    """
    Return all resource addresses affected by
    the Terraform plan.
    """

    changes = get_planned_changes(
        plan
    )

    addresses = []

    for change in changes:
        address = change.get(
            "address"
        )

        if address:
            addresses.append(
                address
            )

    return addresses


def get_change_actions(
    change: dict[str, Any],
) -> list[str]:
    """
    Return the Terraform actions associated with
    one resource change.
    """

    change_details = change.get(
        "change",
        {}
    )

    actions = change_details.get(
        "actions",
        [],
    )

    if not isinstance(
        actions,
        list,
    ):
        return []

    return [
        str(action)
        for action in actions
    ]


def verify_plan_changes(
    plan: dict[str, Any],
    expected_resource: str,
) -> dict[str, Any]:
    """
    Verify that Terraform's planned changes only affect
    the expected resource and use allowed actions.

    Destroy operations are blocked.
    """

    if not expected_resource:
        return {
            "safe": False,
            "reason": (
                "Expected Terraform resource "
                "was not provided."
            ),
        }

    changes = get_planned_changes(
        plan
    )

    if not changes:
        return {
            "safe": False,
            "reason": (
                "Terraform plan contains no "
                "resource changes."
            ),
        }

    unexpected_resources = []
    blocked_actions = []

    for change in changes:
        address = change.get(
            "address"
        )

        actions = get_change_actions(
            change
        )

        if address != expected_resource:
            unexpected_resources.append(
                address
            )

        for action in actions:
            if action not in ALLOWED_ACTIONS:
                blocked_actions.append(
                    {
                        "resource": address,
                        "action": action,
                    }
                )

    if unexpected_resources:
        return {
            "safe": False,
            "reason": (
                "Terraform plan contains "
                "unexpected resources."
            ),
            "unexpected_resources": (
                unexpected_resources
            ),
        }

    if blocked_actions:
        return {
            "safe": False,
            "reason": (
                "Terraform plan contains "
                "blocked actions."
            ),
            "blocked_actions": blocked_actions,
        }

    return {
        "safe": True,
        "reason": (
            "Terraform plan only affects the "
            "expected resource using allowed actions."
        ),
        "resource": expected_resource,
        "actions": [
            action
            for change in changes
            for action in get_change_actions(
                change
            )
        ],
    }


def verify_plan_result(
    plan_result: dict[str, Any],
    expected_resource: str,
) -> dict[str, Any]:
    """
    Verify the basic Terraform plan result.

    This does not inspect the detailed resource changes.
    Use verify_plan_changes() for that.
    """

    if not isinstance(
        plan_result,
        dict,
    ):
        return {
            "safe": False,
            "reason": (
                "Terraform plan result must "
                "be a dictionary."
            ),
        }

    if not expected_resource:
        return {
            "safe": False,
            "reason": (
                "Expected Terraform resource "
                "was not provided."
            ),
        }

    if not plan_result.get("success"):
        return {
            "safe": False,
            "reason": (
                "Terraform plan failed. "
                "Apply is blocked."
            ),
        }

    command = plan_result.get(
        "command",
        [],
    )

    if not isinstance(
        command,
        list,
    ):
        return {
            "safe": False,
            "reason": (
                "Terraform command must "
                "be a list."
            ),
        }

    expected_target = (
        f"-target={expected_resource}"
    )

    if expected_target not in command:
        return {
            "safe": False,
            "reason": (
                "Terraform plan was not targeted "
                "at the expected resource."
            ),
        }

    if command[:2] != [
        "terraform",
        "plan",
    ]:
        return {
            "safe": False,
            "reason": (
                "Command is not a Terraform "
                "plan command."
            ),
        }

    return {
        "safe": True,
        "reason": (
            "Terraform plan succeeded and "
            "targets the expected resource."
        ),
    }