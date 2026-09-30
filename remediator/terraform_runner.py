from pathlib import Path
import re
import subprocess
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]

TERRAFORM_DIRECTORY = (
    PROJECT_ROOT / "terraform-lab"
)

RESOURCE_ADDRESS_PATTERN = re.compile(
    r"^[a-zA-Z0-9_]+"
    r"\.[a-zA-Z0-9_]+"
    r"(?:\[[0-9]+\])?$"
)

print(RESOURCE_ADDRESS_PATTERN)

def validate_resource_address(
    resource: str,
) -> None:
    """
    Validate that a Terraform resource address has
    an allowed basic resource-address format.

    This prevents arbitrary shell arguments from being
    passed to Terraform.
    """

    if not isinstance(resource, str):
        raise ValueError(
            "Terraform resource must be a string."
        )

    if not RESOURCE_ADDRESS_PATTERN.fullmatch(
        resource
    ):
        raise ValueError(
            f"Invalid Terraform resource address: "
            f"{resource}"
        )


def build_plan_command(
    resource: str,
) -> list[str]:
    """
    Build a Terraform plan command targeting exactly
    one validated resource.
    """

    validate_resource_address(resource)

    return [
        "terraform",
        "plan",
        f"-target={resource}",
    ]


def build_apply_command(
    resource: str,
    auto_approve: bool = False,
) -> list[str]:
    """
    Build a Terraform apply command targeting exactly
    one validated resource.

    auto_approve defaults to False so that an explicit
    approval is required unless the caller deliberately
    enables it.
    """

    validate_resource_address(resource)

    command = [
        "terraform",
        "apply",
        f"-target={resource}",
    ]

    if auto_approve:
        command.append(
            "-auto-approve"
        )

    return command


def run_terraform_command(
    command: list[str],
    terraform_directory: Path = TERRAFORM_DIRECTORY,
) -> dict[str, Any]:
    """
    Execute a Terraform command and return its result.

    This function does not construct commands itself.
    The caller must provide a validated command.
    """

    result = subprocess.run(
        command,
        cwd=terraform_directory,
        capture_output=True,
        text=True,
        check=False,
    )

    return {
        "command": command,
        "return_code": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "success": (
            result.returncode == 0
        ),
    }


def terraform_plan(
    resource: str,
    terraform_directory: Path = TERRAFORM_DIRECTORY,
) -> dict[str, Any]:
    """
    Run a targeted Terraform plan.
    """

    command = build_plan_command(
        resource
    )

    return run_terraform_command(
        command,
        terraform_directory,
    )


def terraform_apply(
    resource: str,
    auto_approve: bool = False,
    terraform_directory: Path = TERRAFORM_DIRECTORY,
) -> dict[str, Any]:
    """
    Run a targeted Terraform apply.

    auto_approve must be explicitly enabled by the
    caller.
    """

    command = build_apply_command(
        resource,
        auto_approve=auto_approve,
    )

    return run_terraform_command(
        command,
        terraform_directory,
    )