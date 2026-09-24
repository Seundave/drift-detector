import json

from scorer.report_generator import (
    build_slack_payload,
)


def test_slack_payload_contains_all_severities():
    scored_drifts = [
        {
            "resource": "aws_security_group.web",
            "resource_type": "security_group",
            "environment": "prod",
            "field": "ingress[0].from_port",
            "expected": 80,
            "live": 443,
            "score": 81,
            "severity": "CRITICAL",
        },
        {
            "resource": "aws_instance.web",
            "resource_type": "ec2",
            "environment": "prod",
            "field": "instance_type",
            "expected": "t3.micro",
            "live": "t3.small",
            "score": 42,
            "severity": "HIGH",
        },
        {
            "resource": "aws_instance.web",
            "resource_type": "ec2",
            "environment": "dev",
            "field": "instance_type",
            "expected": "t3.micro",
            "live": "t3.small",
            "score": 14,
            "severity": "MEDIUM",
        },
        {
            "resource": "aws_instance.web",
            "resource_type": "ec2",
            "environment": "dev",
            "field": "tags.Name",
            "expected": "web-server",
            "live": "test-server",
            "score": 1,
            "severity": "LOW",
        },
    ]

    payload = build_slack_payload(
        scored_drifts
    )

    serialized = str(payload)

    print("\n--- SLACK PAYLOAD (JSON) ---")
    print(json.dumps(payload, indent=2))

    assert "CRITICAL" in serialized
    assert "HIGH" in serialized
    assert "MEDIUM" in serialized
    assert "LOW" in serialized

    assert (
        "aws_security_group.web"
        in serialized
    )

    assert (
        "aws_instance.web"
        in serialized
    )

if __name__ == "__main__":
    test_slack_payload_contains_all_severities()