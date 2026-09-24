from scorer.scorer import score_drift


def test_critical_security_group_drift():
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

    assert result["score"] == 81
    assert result["severity"] == "CRITICAL"


def test_high_ec2_drift():
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

    assert result["score"] == 42
    assert result["severity"] == "HIGH"


def test_high_s3_drift():
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

    assert result["score"] == 30
    assert result["severity"] == "HIGH"


def test_medium_dev_ec2_drift():
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

    print(result)
    print(result["score"])

    assert result["score"] == 14
    assert result["severity"] == "MEDIUM"


def test_low_dev_tag_drift():
    drift = {
        "resource": "aws_instance.web",
        "field": "tags.Name",
        "expected": "web-server",
        "live": "test-server",
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

    assert result["score"] == 1
    assert result["severity"] == "LOW"


if __name__ == "__main__":
    test_critical_security_group_drift()
    test_high_ec2_drift()
    test_high_s3_drift()
    test_medium_dev_ec2_drift()
    test_low_dev_tag_drift()