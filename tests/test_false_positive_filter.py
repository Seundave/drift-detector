import json
from scanner.false_positive_filter import filter_differences


def test_keeps_real_tag_drift():
    differences = {
        "values_changed": {
            "root['aws_s3_bucket.app']['attributes']['tags']['Environment']": {
                "new_value": "production",
                "old_value": "dev",
            }
        }
    }

    result = filter_differences(differences)

    assert result == differences
    print("--- Real tag drift kept ---")
    print(json.dumps(result, indent=2))


def test_removes_aws_managed_tag_drift():
    differences = {
        "dictionary_item_added": {
            "root['aws_s3_bucket.app']['attributes']['tags']['aws:createdBy']": {
                "value": "some-service"
            }
        }
    }

    result = filter_differences(differences)

    assert result == {}

    


def test_keeps_non_tag_drift():
    differences = {
        "values_changed": {
            "root['aws_s3_bucket.app']['attributes']['region']": {
                "new_value": "eu-west-1",
                "old_value": "eu-north-1",
            }
        }
    }

    result = filter_differences(differences)

    assert result == differences

    print("--- AWS-managed tag drift removed ---")
    print(json.dumps(result, indent=2))


def test_removes_aws_prefix_tags():
    differences = {
        "dictionary_item_added": {
            "root['aws_s3_bucket.app']['attributes']['tags']['aws:someServiceTag']": {
                "value": "something"
            }
        }
    }

    result = filter_differences(differences)

    assert result == {}


def test_timestamp_difference_is_ignored():
    differences = {
        "values_changed": {
            (
                "root['aws_instance.web']"
                "['attributes']['launch_time']"
            ): {
                "old_value": "2026-09-20T10:00:00",
                "new_value": "2026-09-21T10:00:00",
            }
        }
    }

    result = filter_differences(
        differences
    )

    assert result == {}


def test_computed_attribute_difference_is_ignored():
    differences = {
        "values_changed": {
            (
                "root['aws_instance.web']"
                "['attributes']['created_at']"
            ): {
                "old_value": "2026-09-20",
                "new_value": "2026-09-21",
            }
        }
    }

    result = filter_differences(
        differences
    )

    assert result == {}


def test_real_security_group_drift_is_kept():
    differences = {
        "values_changed": {
            (
                "root['aws_security_group.web']"
                "['attributes']['ingress']"
            ): {
                "old_value": [
                    {
                        "from_port": 80
                    }
                ],
                "new_value": [
                    {
                        "from_port": 443
                    }
                ],
            }
        }
    }

    result = filter_differences(
        differences
    )

    assert result == differences


if __name__ == "__main__":
    
    differences= test_keeps_real_tag_drift()

    print(json.dumps(differences, indent=2))