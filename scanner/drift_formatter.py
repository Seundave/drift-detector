from typing import Any


def extract_resource_and_field(
    path: str,
) -> tuple[str, str]:
    """
    Convert a DeepDiff path into a resource address
    and a human-readable field path.

    Example:

    root['aws_security_group.web']
    ['attributes']['ingress'][0]['from_port']

    becomes:

    (
        "aws_security_group.web",
        "ingress[0].from_port",
    )
    """

    path = path.removeprefix("root")

    parts = []
    current = ""
    index = 0

    while index < len(path):
        if path[index] == "[":
            end = path.find("]", index)

            if end == -1:
                break

            content = path[index + 1:end]

            if (
                content.startswith("'")
                and content.endswith("'")
            ):
                value = content[1:-1]

                if value == "attributes":
                    index = end + 1
                    continue

                if not parts:
                    parts.append(value)
                else:
                    parts.append(
                        f".{value}"
                    )

            else:
                parts.append(
                    f"[{content}]"
                )

            index = end + 1
            continue

        index += 1

    if not parts:
        return "", ""

    resource = parts[0]

    field = "".join(parts[1:])

    return resource, field.lstrip(".")


def format_difference(
    difference_type: str,
    path: str,
    details: Any,
) -> dict[str, Any]:
    """
    Convert one DeepDiff difference into a
    human-readable drift record.
    """

    resource, field = extract_resource_and_field(
        path
    )

    result = {
        "resource": resource,
        "field": field,
        "difference_type": difference_type,
    }

    if difference_type == "values_changed":
        result["expected"] = details.get(
            "old_value"
        )
        result["live"] = details.get(
            "new_value"
        )

    elif difference_type == "dictionary_item_added":
        result["expected"] = None
        result["live"] = details

    elif difference_type == "dictionary_item_removed":
        result["expected"] = details
        result["live"] = None

    elif difference_type == "iterable_item_added":
        result["expected"] = None
        result["live"] = details

    elif difference_type == "iterable_item_removed":
        result["expected"] = details
        result["live"] = None

    else:
        result["details"] = details

    return result


def format_differences(
    differences: dict[str, Any],
) -> list[dict[str, Any]]:
    """
    Convert all DeepDiff differences into a list
    of human-readable drift records.
    """

    formatted_differences = []

    for difference_type, difference_values in (
        differences.items()
    ):
        if not isinstance(
            difference_values,
            dict,
        ):
            continue

        for path, details in difference_values.items():
            formatted_differences.append(
                format_difference(
                    difference_type,
                    path,
                    details,
                )
            )

    return formatted_differences


def print_drift_report(
    differences: list[dict[str, Any]],
) -> None:
    """
    Print a human-readable drift report.
    """

    if not differences:
        print(
            "\nNO ACTIONABLE DRIFT DETECTED"
        )
        return

    print("\nDRIFT DETECTED")
    print("=" * 60)

    for difference in differences:
        print(
            f"\nResource: "
            f"{difference['resource']}"
        )

        print(
            f"Field:    "
            f"{difference['field']}"
        )

        if "expected" in difference:
            print(
                f"\nExpected: "
                f"{difference['expected']}"
            )

            print(
                f"Live:     "
                f"{difference['live']}"
            )

        print(
            f"Type:     "
            f"{difference['difference_type']}"
        )

        print("-" * 60)