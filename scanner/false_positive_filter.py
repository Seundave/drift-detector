from typing import Any


IGNORED_TAG_PREFIXES = (
    "aws:",
)

IGNORED_TAG_KEYS = {
    "aws:createdBy",
}


def is_ignored_tag(tag_key: str) -> bool:
    """
    Return True when a tag should be ignored during drift detection.
    """

    if tag_key in IGNORED_TAG_KEYS:
        return True

    return tag_key.startswith(IGNORED_TAG_PREFIXES)


def filter_differences(
    differences: dict[str, Any],
) -> dict[str, Any]:
    """
    Remove known false-positive differences from DeepDiff output.

    The original differences are not modified.
    """

    filtered_differences: dict[str, Any] = {}

    for difference_type, difference_values in differences.items():
        filtered_values = {}

        for path, details in difference_values.items():
            if "['tags']" in path:
                tag_key = path.split("['")[-1].rstrip("']")

                if is_ignored_tag(tag_key):
                    continue

            filtered_values[path] = details

        if filtered_values:
            filtered_differences[difference_type] = filtered_values

    return filtered_differences