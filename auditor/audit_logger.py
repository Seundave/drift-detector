import json
import os
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

import boto3


DEFAULT_AUDIT_PREFIX = "drift-detector/audit"


def create_audit_record(
    *,
    resource: str,
    environment: str,
    score: int,
    severity: str,
    action: str,
    reason: str,
    status: str,
    terraform_command: list[str] | None = None,
    return_code: int | None = None,
    run_id: str | None = None,
) -> dict[str, Any]:
    """
    Create a structured audit record.

    Terraform stdout/stderr are intentionally not stored here
    because command output can contain sensitive information.
    """

    return {
        "timestamp": datetime.now(
            timezone.utc
        ).isoformat(),
        "run_id": run_id or uuid4().hex,
        "resource": resource,
        "environment": environment,
        "score": score,
        "severity": severity,
        "action": action,
        "reason": reason,
        "status": status,
        "terraform_command": terraform_command,
        "return_code": return_code,
    }


def serialize_audit_record(
    record: dict[str, Any],
) -> str:
    """
    Serialize an audit record as exactly one JSON line.
    """

    return (
        json.dumps(
            record,
            default=str,
            separators=(",", ":"),
        )
        + "\n"
    )


def build_audit_s3_key(
    *,
    run_id: str,
    timestamp: str,
    prefix: str = DEFAULT_AUDIT_PREFIX,
) -> str:
    """
    Build a date-partitioned S3 key.

    Example:

    drift-detector/audit/2026/09/30/abc123.jsonl
    """

    date = datetime.fromisoformat(
        timestamp.replace("Z", "+00:00")
    )

    return (
        f"{prefix.rstrip('/')}/"
        f"{date:%Y/%m/%d}/"
        f"{run_id}.jsonl"
    )


def write_audit_record(
    record: dict[str, Any],
    *,
    bucket: str | None = None,
    prefix: str | None = None,
    s3_client: Any | None = None,
) -> dict[str, Any]:
    """
    Write one audit record to S3 as a JSONL object.

    The bucket can be passed explicitly or configured with:

        AUDIT_S3_BUCKET

    The prefix can be passed explicitly or configured with:

        AUDIT_S3_PREFIX
    """

    bucket_name = (
        bucket
        or os.environ.get("AUDIT_S3_BUCKET")
    )

    if not bucket_name:
        raise ValueError(
            "AUDIT_S3_BUCKET environment variable "
            "must be configured."
        )

    audit_prefix = (
        prefix
        or os.getenv(
            "AUDIT_S3_PREFIX",
            DEFAULT_AUDIT_PREFIX,
        )
    )

    run_id = record.get("run_id")

    if not run_id:
        raise ValueError(
            "Audit record must contain a run_id."
        )

    timestamp = record.get("timestamp")

    if not timestamp:
        raise ValueError(
            "Audit record must contain a timestamp."
        )

    key = build_audit_s3_key(
        run_id=run_id,
        timestamp=timestamp,
        prefix=audit_prefix,
    )

    client = (
        s3_client
        if s3_client is not None
        else boto3.client("s3")
    )

    body = serialize_audit_record(record)

    client.put_object(
        Bucket=bucket_name,
        Key=key,
        Body=body.encode("utf-8"),
        ContentType="application/x-ndjson",
    )

    return {
        "bucket": bucket_name,
        "key": key,
        "run_id": run_id,
    }