from scanner.differ import compare_states

from scanner.differ import compare_states

# Test a state with no drift
def test_compare_states_returns_no_drift_when_states_match():
    expected_state = {
        "aws_s3_bucket.app": {
            "type": "aws_s3_bucket",
            "name": "app",
            "provider": "aws",
            "attributes": {
                "bucket": "drift-detector-app",
                "region": "eu-west-1",
                "tags": {
                    "Environment": "dev"
                }
            }
        }
    }

    live_state = {
        "aws_s3_bucket.app": {
            "type": "aws_s3_bucket",
            "name": "app",
            "provider": "aws",
            "attributes": {
                "bucket": "drift-detector-app",
                "region": "eu-west-1",
                "tags": {
                    "Environment": "dev"
                }
            }
        }
    }

    differences = compare_states(
        expected_state,
        live_state,
    )

    assert differences == {}


# Test actual drift
def test_compare_states_detects_attribute_drift():
    expected_state = {
        "aws_s3_bucket.app": {
            "type": "aws_s3_bucket",
            "name": "app",
            "provider": "aws",
            "attributes": {
                "bucket": "drift-detector-app",
                "region": "eu-west-1",
                "tags": {
                    "Environment": "dev"
                }
            }
        }
    }

    live_state = {
        "aws_s3_bucket.app": {
            "type": "aws_s3_bucket",
            "name": "app",
            "provider": "aws",
            "attributes": {
                "bucket": "drift-detector-app",
                "region": "eu-west-1",
                "tags": {
                    "Environment": "production"
                }
            }
        }
    }

    differences = compare_states(
        expected_state,
        live_state,
    )

    print(differences)

    assert "values_changed" in differences


# Test a resource that exists only in Terraform
def test_compare_states_detects_missing_live_resource():
    expected_state = {
        "aws_s3_bucket.app": {
            "type": "aws_s3_bucket",
            "name": "app",
            "provider": "aws",
            "attributes": {
                "bucket": "drift-detector-app"
            }
        }
    }

    live_state = {}

    differences = compare_states(
        expected_state,
        live_state,
    )

    assert "dictionary_item_removed" in differences



# Test an unexpected live resource
def test_compare_states_detects_unexpected_live_resource():
    expected_state = {}

    live_state = {
        "aws_s3_bucket.unmanaged": {
            "type": "aws_s3_bucket",
            "name": "unmanaged",
            "provider": "aws",
            "attributes": {
                "bucket": "someone-created-this"
            }
        }
    }

    differences = compare_states(
        expected_state,
        live_state,
    )

    assert "dictionary_item_added" in differences