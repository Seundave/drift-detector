import pytest

from remediator.plan_verifier import (
    get_change_actions,
    get_change_addresses,
    parse_plan_json,
    verify_plan_changes,
    verify_plan_result,
)


def make_successful_plan(
    resource: str = "aws_instance.web",
) -> dict:
    return {
        "command": [
            "terraform",
            "plan",
            f"-target={resource}",
        ],
        "return_code": 0,
        "stdout": "Plan succeeded",
        "stderr": "",
        "success": True,
    }


def make_plan_json(
    resource: str = "aws_instance.web",
    actions: list[str] | None = None,
) -> dict:
    return {
        "resource_changes": [
            {
                "address": resource,
                "change": {
                    "actions": (
                        actions
                        or ["update"]
                    ),
                },
            }
        ]
    }


def test_successful_targeted_plan_is_safe():
    plan_result = make_successful_plan()

    result = verify_plan_result(
        plan_result=plan_result,
        expected_resource="aws_instance.web",
    )

    assert result["safe"] is True


def test_failed_plan_is_not_safe():
    plan_result = make_successful_plan()

    plan_result["success"] = False
    plan_result["return_code"] = 1

    result = verify_plan_result(
        plan_result=plan_result,
        expected_resource="aws_instance.web",
    )

    assert result["safe"] is False


def test_wrong_resource_is_not_safe():
    plan_result = make_successful_plan(
        resource="aws_instance.database",
    )

    result = verify_plan_result(
        plan_result=plan_result,
        expected_resource="aws_instance.web",
    )

    assert result["safe"] is False


def test_missing_resource_is_not_safe():
    plan_result = make_successful_plan()

    result = verify_plan_result(
        plan_result=plan_result,
        expected_resource="",
    )

    assert result["safe"] is False


def test_non_terraform_plan_is_not_safe():
    plan_result = {
        "command": [
            "terraform",
            "apply",
            "-target=aws_instance.web",
        ],
        "return_code": 0,
        "stdout": "",
        "stderr": "",
        "success": True,
    }

    result = verify_plan_result(
        plan_result=plan_result,
        expected_resource="aws_instance.web",
    )

    assert result["safe"] is False


def test_non_list_command_is_not_safe():
    plan_result = make_successful_plan()

    plan_result["command"] = (
        "terraform plan "
        "-target=aws_instance.web"
    )

    result = verify_plan_result(
        plan_result=plan_result,
        expected_resource="aws_instance.web",
    )

    assert result["safe"] is False


def test_parse_valid_plan_json():
    plan_json = """
    {
        "resource_changes": []
    }
    """

    result = parse_plan_json(
        plan_json
    )

    assert result == {
        "resource_changes": []
    }


def test_invalid_plan_json_is_rejected():
    with pytest.raises(ValueError):
        parse_plan_json(
            "not valid json"
        )


def test_get_planned_resource_addresses():
    plan = make_plan_json()

    addresses = get_change_addresses(
        plan
    )

    assert addresses == [
        "aws_instance.web"
    ]


def test_get_change_actions():
    change = {
        "address": "aws_instance.web",
        "change": {
            "actions": [
                "update"
            ]
        },
    }

    actions = get_change_actions(
        change
    )

    assert actions == [
        "update"
    ]


def test_expected_update_is_safe():
    plan = make_plan_json(
        actions=["update"]
    )

    result = verify_plan_changes(
        plan=plan,
        expected_resource="aws_instance.web",
    )

    assert result["safe"] is True
    assert result["actions"] == [
        "update"
    ]


def test_expected_create_is_safe():
    plan = make_plan_json(
        actions=["create"]
    )

    result = verify_plan_changes(
        plan=plan,
        expected_resource="aws_instance.web",
    )

    assert result["safe"] is True


def test_unexpected_resource_is_blocked():
    plan = {
        "resource_changes": [
            {
                "address": "aws_instance.web",
                "change": {
                    "actions": [
                        "update"
                    ]
                },
            },
            {
                "address": "aws_security_group.db",
                "change": {
                    "actions": [
                        "update"
                    ]
                },
            },
        ]
    }

    result = verify_plan_changes(
        plan=plan,
        expected_resource="aws_instance.web",
    )

    assert result["safe"] is False

    assert (
        "aws_security_group.db"
        in result["unexpected_resources"]
    )


def test_delete_action_is_blocked():
    plan = make_plan_json(
        actions=["delete"]
    )

    result = verify_plan_changes(
        plan=plan,
        expected_resource="aws_instance.web",
    )

    assert result["safe"] is False

    assert result["blocked_actions"] == [
        {
            "resource": "aws_instance.web",
            "action": "delete",
        }
    ]


def test_replace_action_is_blocked():
    plan = make_plan_json(
        actions=[
            "create",
            "delete",
        ]
    )

    result = verify_plan_changes(
        plan=plan,
        expected_resource="aws_instance.web",
    )

    assert result["safe"] is False

    assert {
        "resource": "aws_instance.web",
        "action": "delete",
    } in result["blocked_actions"]


def test_empty_plan_is_not_safe():
    plan = {
        "resource_changes": []
    }

    result = verify_plan_changes(
        plan=plan,
        expected_resource="aws_instance.web",
    )

    assert result["safe"] is False