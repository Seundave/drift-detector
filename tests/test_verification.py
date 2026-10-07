from scanner.verification import (
    extract_resource_differences,
    verify_resource,
)


def make_terraform_state(
    instance_type: str = "t3.micro",
) -> dict:
    return {
        "resources": [
            {
                "mode": "managed",
                "type": "aws_instance",
                "name": "web",
                "provider": (
                    'provider["registry.terraform.io/'
                    'hashicorp/aws"]'
                ),
                "instances": [
                    {
                        "attributes": {
                            "instance_type": instance_type,
                        }
                    }
                ],
            }
        ]
    }


def make_live_state(
    instance_type: str = "t3.micro",
) -> dict:
    return {
        "aws_instance.web": {
            "type": "aws_instance",
            "name": "web",
            "provider": "aws",
            "attributes": {
                "instance_id": None,
                "instance_type": instance_type,
                "ami": None,
                "availability_zone": None,
                "subnet_id": None,
                "security_groups": [],
                "state": "running",
                "tags": {},
            },
        }
    }


def test_resource_is_verified_when_drift_is_resolved():
    terraform_state = make_terraform_state(
        instance_type="t3.micro"
    )

    live_state = make_live_state(
        instance_type="t3.micro"
    )

    result = verify_resource(
        terraform_state=terraform_state,
        live_state=live_state,
        resource="aws_instance.web",
    )


    print("Terraform State:", terraform_state)
    print("Live State:", live_state)
    print("Verification Result:", result)

    assert result["drift_resolved"] is True

    assert result["differences"] == {}


def test_resource_verification_fails_when_drift_remains():
    terraform_state = make_terraform_state(
        instance_type="t3.micro"
    )

    live_state = make_live_state(
        instance_type="t3.small"
    )

    result = verify_resource(
        terraform_state=terraform_state,
        live_state=live_state,
        resource="aws_instance.web",
    )

    assert result["drift_resolved"] is False

    assert result["differences"]


def test_extract_resource_differences_only_returns_target_resource():
    differences = {
        "values_changed": {
            (
                "root['aws_instance.web']"
                "['attributes']['instance_type']"
            ): {
                "old_value": "t3.micro",
                "new_value": "t3.small",
            },
            (
                "root['aws_security_group.web']"
                "['attributes']['description']"
            ): {
                "old_value": "old",
                "new_value": "new",
            },
        }
    }

    result = extract_resource_differences(
        differences= differences,
        resource="aws_instance.web",
    )

    assert (
        "values_changed"
        in result
    )

    assert len(
        result["values_changed"]
    ) == 1

    assert (
        "aws_instance.web"
        in next(
            iter(
                result[
                    "values_changed"
                ]
            )
        )
    )


def test_no_differences_means_drift_is_resolved():
    result = verify_resource(
        terraform_state=make_terraform_state(),
        live_state=make_live_state(),
        resource="aws_instance.web",
    )

    assert result["drift_resolved"] is True


if __name__ == "__main__":
    test_resource_is_verified_when_drift_is_resolved()