from typing import Any

from scanner.differ import compare_states
from scanner.false_positive_filter import (
    filter_differences,
)
from scanner.normaliser import normalise_state


def verify_resource(
    *,
    terraform_state: dict[str, Any],
    live_state: dict[str, Any],
    resource: str,
) -> dict[str, Any]:
    """
    Verify whether a Terraform-managed resource still
    has actionable drift after remediation.

    The Terraform state and live AWS state are normalized
    before comparison.

    False-positive differences are removed before the
    final verification decision.
    """

    expected_state = normalise_state(
        terraform_state
    )

    differences = compare_states(
        expected_state,
        live_state,
    )

    filtered_differences = (
        filter_differences(
            differences
        )
    )

    resource_differences = (
        extract_resource_differences(
            filtered_differences,
            resource,
        )
    )

    drift_resolved = (
        len(resource_differences) == 0
    )

    return {
        "resource": resource,
        "drift_resolved": drift_resolved,
        "differences": resource_differences,
    }


def extract_resource_differences(
    differences: dict[str, Any],
    resource: str,
) -> dict[str, Any]:
    """
    Extract only differences belonging to the
    resource being verified.
    """

    resource_differences: dict[str, Any] = {}

    resource_prefix = (
        f"root['{resource}']"
    )

    for difference_type, values in (
        differences.items()
    ):
        if not isinstance(values, dict):
            continue

        matching_values = {}

        for path, details in values.items():
            if path.startswith(
                resource_prefix
            ):
                matching_values[path] = details

        if matching_values:
            resource_differences[
                difference_type
            ] = matching_values

    return resource_differences
