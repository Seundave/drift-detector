from pathlib import Path
from typing import Any

import yaml


BASE_DIR = Path(__file__).resolve().parents[1]

REMEDIATION_RULES_PATH = (
    BASE_DIR
    / "config"
    / "remediation_rules.yaml"
)

print(f"REMEDIATION_RULES_PATH: {REMEDIATION_RULES_PATH}")

PROTECTED_RESOURCES_PATH = (
    BASE_DIR
    / "config"
    / "protected_resources.yaml"
)

print(f"PROTECTED_RESOURCES_PATH: {PROTECTED_RESOURCES_PATH}")


def load_yaml_file(
    path: Path,
) -> dict[str, Any]:
    """
    Load a YAML configuration file.
    """

    with path.open(
        "r",
        encoding="utf-8",
    ) as file:
        config = yaml.safe_load(file)

        print(
            f"Loaded configuration from {path}: {config}"
        )

    if not isinstance(config, dict):
        raise ValueError(
            f"Configuration must be a YAML mapping: {path}"
        )

    return config


def load_remediation_rules() -> dict[str, Any]:
    """
    Load remediation policy configuration.
    """

    return load_yaml_file(
        REMEDIATION_RULES_PATH
    )


def load_protected_resources() -> set[str]:
    """
    Load protected Terraform resource addresses.
    """

    config = load_yaml_file(
        PROTECTED_RESOURCES_PATH
    )

    resources = config.get(
        "protected_resources",
        [],
    )

    if not isinstance(resources, list):
        raise ValueError(
            "protected_resources must be a list."
        )

    return set(resources)


def is_protected_resource(
    resource: str,
    protected_resources: set[str],
) -> bool:
    """
    Return True when a resource is protected
    from automatic remediation.
    """

    return resource in protected_resources


def determine_decision(
    drift: dict[str, Any],
    rules: dict[str, Any],
    protected_resources: set[str],
) -> dict[str, Any]:
    """
    Determine what action should be taken for a
    scored drift.

    This function only makes a decision. It does
    not execute Terraform, send notifications,
    or modify infrastructure.
    """

    resource = drift["resource"]

    environment = str(
        drift.get(
            "environment",
            "",
        )
    ).lower()

    score = int(
        drift.get(
            "score",
            0,
        )
    )

    remediation = rules["remediation"]

    auto_fix = remediation["auto_fix"]
    alert_only = remediation["alert_only"]
    critical = remediation["critical"]

    # Critical drift always takes the critical path.
    if score >= critical["min_score"]:
        return {
            "action": "CRITICAL",
            "resource": resource,
            "score": score,
            "environment": environment,
            "reason": (
                "Drift score meets or exceeds "
                "the critical threshold."
            ),
            "requires_approval": True,
            "notifications": critical[
                "notifications"
            ],
            "block_deployments": critical[
                "block_deployments"
            ],
        }

    # Alert-only score range.
    if (
        alert_only["min_score"]
        <= score
        <= alert_only["max_score"]
    ):
        return {
            "action": "ALERT_ONLY",
            "resource": resource,
            "score": score,
            "environment": environment,
            "reason": (
                "Drift score falls within the "
                "alert-only range."
            ),
            "requires_approval": False,
            "notifications": alert_only[
                "notifications"
            ],
            "block_deployments": False,
        }

    # Scores outside the automatic remediation
    # range must never be automatically fixed.
    if not auto_fix["enabled"]:
        return {
            "action": "ALERT_ONLY",
            "resource": resource,
            "score": score,
            "environment": environment,
            "reason": (
                "Automatic remediation is disabled."
            ),
            "requires_approval": True,
            "notifications": {
                "slack": True,
            },
            "block_deployments": False,
        }

    if score > auto_fix["max_score"]:
        return {
            "action": "ALERT_ONLY",
            "resource": resource,
            "score": score,
            "environment": environment,
            "reason": (
                "Drift score exceeds the automatic "
                "remediation threshold."
            ),
            "requires_approval": True,
            "notifications": {
                "slack": True,
            },
            "block_deployments": False,
        }

    allowed_environments = {
        str(environment_name).lower()
        for environment_name in auto_fix[
            "allowed_environments"
        ]
    }

    if environment not in allowed_environments:
        return {
            "action": "ALERT_ONLY",
            "resource": resource,
            "score": score,
            "environment": environment,
            "reason": (
                "Automatic remediation is only "
                "allowed in configured environments."
            ),
            "requires_approval": True,
            "notifications": {
                "slack": True,
            },
            "block_deployments": False,
        }

    if (
        auto_fix["require_not_protected"]
        and is_protected_resource(
            resource,
            protected_resources,
        )
    ):
        return {
            "action": "ALERT_ONLY",
            "resource": resource,
            "score": score,
            "environment": environment,
            "reason": (
                "Resource is protected from "
                "automatic remediation."
            ),
            "requires_approval": True,
            "notifications": {
                "slack": True,
            },
            "block_deployments": False,
        }

    terraform_config = auto_fix[
        "terraform"
    ]

    return {
        "action": "AUTO_FIX",
        "resource": resource,
        "score": score,
        "environment": environment,
        "reason": (
            "Low-risk drift is eligible for "
            "automatic remediation."
        ),
        "requires_approval": False,
        "notifications": {},
        "block_deployments": False,
        "terraform": {
            "command": terraform_config[
                "command"
            ],
            "target": terraform_config[
                "target"
            ],
            "auto_approve": terraform_config[
                "auto_approve"
            ],
        },
    }


def decide(
    drift: dict[str, Any],
) -> dict[str, Any]:
    """
    Load configuration and determine the
    remediation decision for a single drift.
    """

    rules = load_remediation_rules()

    protected_resources = (
        load_protected_resources()
    )

    return determine_decision(
        drift=drift,
        rules=rules,
        protected_resources=protected_resources,
    )


def decide_remediation(
    drift: dict[str, Any],
) -> dict[str, Any]:
    """
    Compatibility wrapper used by the remediation
    orchestrator.

    The actual decision logic remains inside
    decide() and determine_decision().
    """

    return decide(drift)
