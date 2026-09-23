from scorer.report_generator import (
    build_severity_summary,
    build_slack_payload,
    generate_report,
)

def test_build_severity_summary():
    scored_drifts = [
        {
            "severity": "CRITICAL",
        },
        {
            "severity": "HIGH",
        },
        {
            "severity": "LOW",
        },
        {
            "severity": "LOW",
        },
    ]

    summary = build_severity_summary(
        scored_drifts
    )

    assert summary == {
        "critical": 1,
        "high": 1,
        "medium": 0,
        "low": 2,
    }



def test_generate_report(tmp_path):
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
        }
    ]

    output_path = (
        tmp_path / "drift-report.json"
    )

    report = generate_report(
        scored_drifts,
        output_path=str(output_path),
    )

    assert report["drift_detected"] is True
    assert report["difference_count"] == 1
    assert (
        report["severity_summary"]["critical"]
        == 1
    )

    assert output_path.exists()



def test_build_slack_payload():
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
            "environment": "dev",
            "field": "tags.Environment",
            "expected": "dev",
            "live": "development",
            "score": 1,
            "severity": "LOW",
        },
    ]

    payload = build_slack_payload(
        scored_drifts
    )

    assert "text" in payload
    assert "blocks" in payload

    assert len(payload["blocks"]) > 0

    serialized = str(payload)

    assert "CRITICAL" in serialized
    assert "LOW" in serialized
    assert "aws_security_group.web" in serialized
    assert "aws_instance.web" in serialized

def test_build_slack_payload_with_no_drift():
    payload = build_slack_payload([])

    assert (
        payload["text"]
        == "No actionable infrastructure drift detected."
    )

    assert len(payload["blocks"]) == 1



if __name__ == "__main__":
    test_build_slack_payload()
    print("All tests passed!")