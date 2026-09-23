from pathlib import Path
from typing import Any

import yaml


MATRIX_PATH = (
    Path(__file__).resolve().parent
    / "scoring_matrix.yaml"
)


def load_scoring_matrix() -> dict[str, Any]:
    """
    Load the severity scoring configuration
    from scoring_matrix.yaml.
    """

    with MATRIX_PATH.open(
        "r",
        encoding="utf-8",
    ) as file:
        matrix = yaml.safe_load(file)

    if not isinstance(matrix, dict):
        raise ValueError(
            "Scoring matrix must contain a YAML mapping."
        )

    return matrix


def get_resource_type(
    resource: str,
) -> str:
    """
    Convert a Terraform resource address into
    the scoring resource category.
    """

    if resource.startswith(
        "aws_security_group."
    ):
        return "security_group"

    if resource.startswith(
        "aws_instance."
    ):
        return "ec2"

    if resource.startswith(
        "aws_s3_bucket."
    ):
        return "s3"

    if resource.startswith(
        "aws_iam_"
    ):
        return "iam"

    raise ValueError(
        f"Unsupported resource type: {resource}"
    )


def get_environment(
    attributes: dict[str, Any],
) -> str:
    """
    Get the environment from resource tags.
    """

    tags = attributes.get("tags", {})

    environment = tags.get(
        "Environment",
        "dev",
    )

    return str(environment).lower()


def get_attribute_weight(
    field: str,
    matrix: dict[str, Any],
) -> int | None:
    """
    Return a special weight for a specific attribute
    when one is configured.
    """

    attribute_weights = matrix.get(
        "attribute_weights",
        {},
    )

    if field == "tags" or field.startswith(
        "tags."
    ):
        return attribute_weights.get("tags")

    return None


def determine_blast_radius(
    resource_type: str,
    field: str,
) -> str:
    """
    Determine the blast-radius category for a drift.
    """

    if field == "tags" or field.startswith(
        "tags."
    ):
        return "low"

    if resource_type == "security_group":
        return "high"

    if resource_type == "iam":
        return "high"

    if resource_type == "ec2":
        return "medium"

    if resource_type == "s3":
        return "medium"

    return "low"


def calculate_score(
    resource_type: str,
    environment: str,
    field: str,
    matrix: dict[str, Any],
) -> dict[str, Any]:
    """
    Calculate the severity score for a drift.
    """

    resource_weights = matrix[
        "resource_weights"
    ]

    environment_multipliers = matrix[
        "environment_multipliers"
    ]

    blast_radius_values = matrix[
        "blast_radius"
    ]

    attribute_weight = get_attribute_weight(
        field,
        matrix,
    )

    resource_weight = (
        attribute_weight
        if attribute_weight is not None
        else resource_weights[resource_type]
    )

    environment_multiplier = (
        environment_multipliers.get(
            environment,
            environment_multipliers["dev"],
        )
    )

    blast_radius = determine_blast_radius(
        resource_type,
        field,
    )

    blast_radius_multiplier = (
        blast_radius_values[blast_radius]
    )

    score = (
        resource_weight
        * environment_multiplier
        * blast_radius_multiplier
    )

    return {
        "resource_weight": resource_weight,
        "environment_multiplier": (
            environment_multiplier
        ),
        "blast_radius": blast_radius,
        "blast_radius_multiplier": (
            blast_radius_multiplier
        ),
        "score": score,
    }


def get_severity(
    score: int,
    matrix: dict[str, Any],
) -> str:
    """
    Convert a numeric score into a severity level.
    """

    thresholds = matrix[
        "severity_thresholds"
    ]

    for severity, threshold in thresholds.items():
        minimum = threshold["min"]
        maximum = threshold.get("max")

        if maximum is None:
            if score >= minimum:
                return severity.upper()

        elif minimum <= score <= maximum:
            return severity.upper()

    raise ValueError(
        f"No severity threshold matches score: {score}"
    )


def score_drift(
    drift: dict[str, Any],
    attributes: dict[str, Any],
) -> dict[str, Any]:
    """
    Calculate severity information for a single
    drift item.
    """

    matrix = load_scoring_matrix()

    resource = drift["resource"]
    field = drift["field"]

    resource_type = get_resource_type(
        resource
    )

    environment = get_environment(
        attributes
    )

    score_details = calculate_score(
        resource_type=resource_type,
        environment=environment,
        field=field,
        matrix=matrix,
    )

    severity = get_severity(
        score_details["score"],
        matrix,
    )

    return {
        "resource": resource,
        "resource_type": resource_type,
        "environment": environment,
        "field": field,
        "expected": drift.get("expected"),
        "live": drift.get("live"),
        **score_details,
        "severity": severity,
    }
