import json
from pathlib import Path

from scanner.normaliser import normalise_state


FIXTURE_PATH = Path("tests/fixtures/sample.tfstate")


def load_fixture() -> dict:
    """Load the sample Terraform state fixture."""

    with FIXTURE_PATH.open("r", encoding="utf-8") as file:
        return json.load(file)


# Test the attributes
def test_normalise_state_returns_expected_resource():
    state = load_fixture()

    normalized = normalise_state(state)

    assert "aws_s3_bucket.app" in normalized

    resource = normalized["aws_s3_bucket.app"]

    assert resource["type"] == "aws_s3_bucket"
    assert resource["name"] == "app"
    assert resource["provider"] == "aws"

    assert resource["attributes"]["bucket"] == "drift-detector-test-app"
    assert resource["attributes"]["region"] == "eu-west-1"

    assert resource["attributes"]["tags"] == {
        "Name": "drift-detector-test-app",
        "Environment": "dev",
        "ManagedBy": "Terraform",
    }

# Testignoring data resources
def test_normalise_state_ignores_data_resources():
    state = load_fixture()

    normalized = normalise_state(state)

    assert "aws_s3_bucket.app" in normalized
    assert "aws_region.current" not in normalized


# Test multiple instances
def test_normalise_state_handles_multiple_instances():
    state = {
        "resources": [
            {
                "mode": "managed",
                "type": "aws_instance",
                "name": "web",
                "provider": "provider[\"registry.terraform.io/hashicorp/aws\"]",
                "instances": [
                    {
                        "attributes": {
                            "instance_type": "t3.micro"
                        }
                    },
                    {
                        "attributes": {
                            "instance_type": "t3.small"
                        }
                    }
                ]
            }
        ]
    }

    normalized = normalise_state(state)

    assert "aws_instance.web[0]" in normalized
    assert "aws_instance.web[1]" in normalized

    assert (
        normalized["aws_instance.web[0]"]["attributes"]["instance_type"]
        == "t3.micro"
    )

    assert (
        normalized["aws_instance.web[1]"]["attributes"]["instance_type"]
        == "t3.small"
    )

# Test an empty state
def test_normalise_state_handles_empty_state():
    state = {
        "resources": []
    }

    normalized = normalise_state(state)

    assert normalized == {}