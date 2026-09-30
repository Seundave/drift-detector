import json

from unittest.mock import Mock

import pytest

from auditor.audit_logger import (
    build_audit_s3_key,
    create_audit_record,
    serialize_audit_record,
    write_audit_record,
)

def test_create_audit_record():
    record = create_audit_record(
        resource="aws_instance.web",
        environment="dev",
        score=1,
        severity="LOW",
        action="AUTO_FIX",
        reason="Low-risk drift is eligible for automatic remediation.",
        status="SUCCESS",
        terraform_command=[
            "terraform",
            "apply",
            "-target=aws_instance.web",
        ],
        return_code=0,
        run_id="test-run-123",
    )

   

    assert record["run_id"] == "test-run-123"
    assert record["resource"] == "aws_instance.web"
    assert record["environment"] == "dev"
    assert record["score"] == 1
    assert record["severity"] == "LOW"
    assert record["action"] == "AUTO_FIX"
    assert record["status"] == "SUCCESS"
    assert record["return_code"] == 0
    assert record["timestamp"]



def test_create_audit_record_generates_run_id():
    record = create_audit_record(
        resource="aws_instance.web",
        environment="dev",
        score=1,
        severity="LOW",
        action="AUTO_FIX",
        reason="Test remediation.",
        status="SUCCESS",
    )

    

    assert record["run_id"]
    assert isinstance(
        record["run_id"],
        str,
    )


def test_serialize_audit_record_is_one_json_line():
    record = {
        "run_id": "abc123",
        "resource": "aws_instance.web",
        "status": "SUCCESS",
    }

    serialized = serialize_audit_record(
        record
    )

    assert serialized.endswith("\n")
    assert serialized.count("\n") == 1

    parsed = json.loads(serialized)

  

    assert parsed == record


def test_build_audit_s3_key():
    key = build_audit_s3_key(
        run_id="abc123",
        timestamp="2026-09-30T10:00:00+00:00",
        prefix="drift-detector/audit",
    )

    

    assert key == (
        "drift-detector/audit/"
        "2026/09/30/"
        "abc123.jsonl"
    )


def test_write_audit_record():
    s3_client = Mock()

    record = create_audit_record(
        resource="aws_instance.web",
        environment="dev",
        score=1,
        severity="LOW",
        action="AUTO_FIX",
        reason="Low-risk drift.",
        status="SUCCESS",
        terraform_command=[
            "terraform",
            "apply",
            "-target=aws_instance.web",
        ],
        return_code=0,
        run_id="abc123",
    )

    result = write_audit_record(
        record,
        bucket="drift-detector-audit",
        prefix="drift-detector/audit",
        s3_client=s3_client,
    )

    # print("result", result)

    assert result == {
        "bucket": "drift-detector-audit",
        "key": (
            "drift-detector/audit/"
            "2026/09/30/"
            "abc123.jsonl"
        ),
        "run_id": "abc123",
    }

    s3_client.put_object.assert_called_once()

    call_kwargs = (
        s3_client.put_object.call_args.kwargs
    )

    # print(call_kwargs ,"call_kwargs ")

    assert (
        call_kwargs["Bucket"]
        == "drift-detector-audit"
    )

    assert (
        call_kwargs["Key"]
        == "drift-detector/audit/"
        "2026/09/30/abc123.jsonl"
    )

    assert (
        call_kwargs["ContentType"]
        == "application/x-ndjson"
    )

    body = call_kwargs["Body"].decode(
        "utf-8"
    )

    assert body.endswith("\n")

    parsed = json.loads(body)

    assert parsed["resource"] == (
        "aws_instance.web"
    )
    assert parsed["status"] == "SUCCESS"


if __name__ == "__main__":
    test_write_audit_record()