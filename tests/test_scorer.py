from scorer.scorer import (
    get_resource_type,
    get_severity,
    load_scoring_matrix,
    score_drift,
)


def test_load_scoring_matrix():
    matrix = load_scoring_matrix()

    print("Loaded scoring matrix:")
    print(matrix)

    assert "resource_weights" in matrix
    assert "attribute_weights" in matrix
    assert "environment_multipliers" in matrix
    assert "blast_radius" in matrix
    assert "severity_thresholds" in matrix



def test_get_resource_type():
    assert (
        get_resource_type(
            "aws_security_group.web"
        )
        == "security_group"
    )

    assert (
        get_resource_type(
            "aws_instance.web"
        )
        == "ec2"
    )

    assert (
        get_resource_type(
            "aws_s3_bucket.app"
        )
        == "s3"
    )

    assert (
        get_resource_type(
            "aws_iam_policy.example"
        )
        == "iam"
    )


from scorer.scorer import score_drift


def test_production_security_group_is_critical():
    drift = {
        "resource": "aws_security_group.web",
        "field": "ingress[0].from_port",
        "expected": 80,
        "live": 443,
    }

    attributes = {
        "tags": {
            "Environment": "prod"
        }
    }

    result = score_drift(
        drift,
        attributes,
    )

    assert result["resource_type"] == "security_group"
    assert result["environment"] == "prod"
    assert result["score"] == 81
    assert result["severity"] == "CRITICAL"

def test_production_ec2_configuration_is_high():
    drift = {
        "resource": "aws_instance.web",
        "field": "instance_type",
        "expected": "t3.micro",
        "live": "t3.small",
    }

    attributes = {
        "tags": {
            "Environment": "prod"
        }
    }

    result = score_drift(
        drift,
        attributes,
    )

    assert result["resource_type"] == "ec2"
    assert result["environment"] == "prod"
    assert result["score"] == 42
    assert result["severity"] == "HIGH"


def test_production_s3_configuration_is_medium():
    drift = {
        "resource": "aws_s3_bucket.app",
        "field": "region",
        "expected": "eu-north-1",
        "live": "eu-west-1",
    }

    attributes = {
        "tags": {
            "Environment": "prod"
        }
    }

    result = score_drift(
        drift,
        attributes,
    )

    assert result["resource_type"] == "s3"
    assert result["environment"] == "prod"
    assert result["score"] == 30
    assert result["severity"] == "HIGH"


def test_development_ec2_configuration_is_medium():
    drift = {
        "resource": "aws_instance.web",
        "field": "instance_type",
        "expected": "t3.micro",
        "live": "t3.small",
    }

    attributes = {
        "tags": {
            "Environment": "dev"
        }
    }

    result = score_drift(
        drift,
        attributes,
    )

    assert result["resource_type"] == "ec2"
    assert result["environment"] == "dev"
    assert result["score"] == 14
    assert result["severity"] == "MEDIUM"


def test_development_tag_change_is_low():
    drift = {
        "resource": "aws_instance.web",
        "field": "tags.Environment",
        "expected": "dev",
        "live": "development",
    }

    attributes = {
        "tags": {
            "Environment": "dev"
        }
    }

    result = score_drift(
        drift,
        attributes,
    )

    assert result["resource_type"] == "ec2"
    assert result["environment"] == "dev"
    assert result["resource_weight"] == 1
    assert result["blast_radius"] == "low"
    assert result["score"] == 1
    assert result["severity"] == "LOW"


def test_severity_threshold_boundaries():
    matrix = load_scoring_matrix()

    assert get_severity(1, matrix) == "LOW"
    assert get_severity(9, matrix) == "LOW"

    assert get_severity(10, matrix) == "MEDIUM"
    assert get_severity(24, matrix) == "MEDIUM"

    assert get_severity(25, matrix) == "HIGH"
    assert get_severity(49, matrix) == "HIGH"

    assert get_severity(50, matrix) == "CRITICAL"
    assert get_severity(100, matrix) == "CRITICAL"