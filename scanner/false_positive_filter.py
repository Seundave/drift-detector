from typing import Any, Dict, List, Set, Union


IGNORED_TAG_PREFIXES = ("aws:",)

IGNORED_TAG_KEYS = {
    "aws:createdBy",
}

# Timestamp and auto-generated lifecycle metadata fields
IGNORED_ATTRIBUTE_NAMES = {
    "created_at",
    "creation_date",
    "launch_time",
    "last_modified",
    "last_modified_time",
    "updated_at",
    "update_time",
    "timestamp",
}


def is_ignored_tag(tag_key: str) -> bool:
    """
    Return True when a tag should be ignored during drift detection.
    """
    if tag_key in IGNORED_TAG_KEYS:
        return True

    return tag_key.startswith(IGNORED_TAG_PREFIXES)


def is_ignored_attribute(path: str) -> bool:
    """
    Return True when a DeepDiff path points to an ignorable attribute name
    (such as launch times, creation dates, or system tags).
    """
    # 1. Check for ignored timestamp attributes
    for attr in IGNORED_ATTRIBUTE_NAMES:
        if f"['{attr}']" in path or f"['{attr}'" in path:
            return True

    # 2. Check for explicit system tag keys
    for tag_key in IGNORED_TAG_KEYS:
        if f"['{tag_key}']" in path or tag_key in path:
            return True

    # 3. Check for tag prefixes (e.g. aws:cloudformation:stack-id)
    for prefix in IGNORED_TAG_PREFIXES:
        if f"['tags']['{prefix}" in path or f"['tags_all']['{prefix}" in path:
            return True

    return False


def is_false_positive(path: str, details: Dict[str, Any]) -> bool:
    """
    Evaluates whether a value difference is a false positive.
    """
    return is_ignored_attribute(path)


def is_false_positive_path(path: str) -> bool:
    """
    Evaluates whether an added or removed key path is a false positive.
    """
    return is_ignored_attribute(path)


def filter_differences(differences: Dict[str, Any]) -> Dict[str, Any]:
    """
    Filters out known false positives (system tags, timestamps) from DeepDiff results.
    Handles both dict-like diffs (values_changed, type_changes) and list/set diffs
    (dictionary_item_added, dictionary_item_removed).
    """
    filtered: Dict[str, Any] = {}

    for diff_type, difference_values in differences.items():
        # Case 1: Value changes and type changes (dict mapping path -> change details)
        if isinstance(difference_values, dict):
            filtered_category = {}
            for path, details in difference_values.items():
                if not is_false_positive(path, details):
                    filtered_category[path] = details

            if filtered_category:
                filtered[diff_type] = filtered_category

        # Case 2: Structural additions/deletions (SetOrdered / set / list of path strings)
        elif isinstance(difference_values, (set, list)) or hasattr(difference_values, "__iter__"):
            filtered_paths = []
            for path in difference_values:
                if not is_false_positive_path(str(path)):
                    filtered_paths.append(path)

            if filtered_paths:
                filtered[diff_type] = filtered_paths

    return filtered