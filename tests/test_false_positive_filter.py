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


if __name__ == "__main__":
    
    differences= test_keeps_real_tag_drift()

    print(json.dumps(differences, indent=2))