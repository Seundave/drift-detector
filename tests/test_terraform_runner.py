import pytest
from unittest.mock import patch

from remediator.terraform_runner import (
    run_terraform_command,
)

from remediator.terraform_runner import (
    build_apply_command,
    build_plan_command,
    validate_resource_address,
)


def test_valid_resource_address():
    validate_resource_address(
        "aws_instance.web"
    )


def test_valid_indexed_resource_address():
    validate_resource_address(
        "aws_instance.web[0]"
    )


def test_invalid_resource_address_is_rejected():
    with pytest.raises(ValueError):
        validate_resource_address(
            "aws_instance.web;rm -rf /"
        )


def test_invalid_shell_command_is_rejected():
    with pytest.raises(ValueError):
        validate_resource_address(
            "aws_instance.web && echo hacked"
        )


def test_plan_command():
    command = build_plan_command(
        "aws_instance.web"
    )

    print("COMMANAAANNDD")
    print(command)

    assert command == [
        "terraform",
        "plan",
        "-target=aws_instance.web",
    ]


def test_apply_command_without_auto_approve():
    command = build_apply_command(
        "aws_instance.web"
    )

    assert command == [
        "terraform",
        "apply",
        "-target=aws_instance.web",
    ]


def test_apply_command_with_auto_approve():
    command = build_apply_command(
        "aws_instance.web",
        auto_approve=True,
    )

    assert command == [
        "terraform",
        "apply",
        "-target=aws_instance.web",
        "-auto-approve",
    ]


def test_run_terraform_command_success():
    with patch(
        "remediator.terraform_runner.subprocess.run"
    ) as mock_run:

        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = (
            "Terraform plan succeeded"
        )
        mock_run.return_value.stderr = ""

        result = run_terraform_command(
            [
                "terraform",
                "plan",
                "-target=aws_instance.web",
            ]
        )

    assert result["success"] is True
    assert result["return_code"] == 0
    assert (
        result["stdout"]
        == "Terraform plan succeeded"
    )

    mock_run.assert_called_once()
