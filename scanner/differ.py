from typing import Any

from deepdiff import DeepDiff


def compare_states(
    expected_state: dict[str, Any],
    live_state: dict[str, Any],
) -> dict[str, Any]:
    """
    Compare normalized Terraform state with normalized live state.

    Returns a dictionary describing detected drift.
    """

    differences = DeepDiff(
        expected_state,
        live_state,
        ignore_order=True,
    )

    return differences.to_dict()