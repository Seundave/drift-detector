from scanner.drift_formatter import (
    extract_resource_and_field,
    format_differences,
)


def test_extract_resource_and_field():
    path = (
        "root['aws_security_group.web']"
        "['attributes']['ingress'][0]"
        "['from_port']"
    )

    resource, field = (
        extract_resource_and_field(path)
    )

    assert resource == (
        "aws_security_group.web"
    )

    assert field == (
        "ingress[0].from_port"
    )


def test_format_values_changed():
    differences = {
        "values_changed": {
            (
                "root['aws_security_group.web']"
                "['attributes']['ingress'][0]"
                "['from_port']"
            ): {
                "old_value": 80,
                "new_value": 443,
            }
        }
    }

    result = format_differences(
        differences
    )

    assert len(result) == 1

    drift = result[0]

    assert (
        drift["resource"]
        == "aws_security_group.web"
    )

    assert (
        drift["field"]
        == "ingress[0].from_port"
    )

    assert drift["expected"] == 80
    assert drift["live"] == 443