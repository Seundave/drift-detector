from typing import Any, Dict


IGNORED_TAG_PREFIXES = ("aws:",)

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


def is_false_positive(path: str, details: Dict[str, Any]) -> bool:
    """
    Evaluates whether a value difference is a false positive (e.g. AWS system tags).
    """
    # Filter out ignored AWS system tags
    for tag_key in IGNORED_TAG_KEYS:
        if tag_key in path:
            return True

    for prefix in IGNORED_TAG_PREFIXES:
        if f"['tags']['{prefix}" in path or f"['tags_all']['{prefix}" in path:
            return True

    return False


def is_false_positive_path(path: str) -> bool:
    """
    Evaluates whether an added or removed key path is a false positive.
    """
    # Filter out added/removed AWS system tags
    for tag_key in IGNORED_TAG_KEYS:
        if tag_key in path:
            return True

    for prefix in IGNORED_TAG_PREFIXES:
        if f"['tags']['{prefix}" in path or f"['tags_all']['{prefix}" in path:
            return True

    return False


def filter_differences(differences: dict) -> dict:
    """
    Filters out known false positives from DeepDiff results.
    """
    filtered = {}

    for diff_type, difference_values in differences.items():
        # Case 1: Value changes (dictionary mapping path -> change details)
        if isinstance(difference_values, dict):
            filtered_category = {}
            for path, details in difference_values.items():
                if not is_false_positive(path, details):
                    filtered_category[path] = details

            if filtered_category:
                filtered[diff_type] = filtered_category

        # Case 2: Structural additions/deletions (SetOrdered / set of path strings)
        elif isinstance(difference_values, (set, list)) or hasattr(difference_values, "__iter__"):
            filtered_paths = []
            for path in difference_values:
                if not is_false_positive_path(path):
                    filtered_paths.append(path)

            if filtered_paths:
                filtered[diff_type] = filtered_paths

    return filtered