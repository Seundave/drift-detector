from unittest.mock import patch

import pytest

from scanner import run_scan


@pytest.fixture
def expected_state():
    return {
        "aws_s3_bucket.app": {
            "type": "aws_s3_bucket",
            "name": "app",
            "provider": "aws",
            "attributes": {
                "bucket": "drift-detector-app-aa3f37b0",
                "region": "eu-north-1",
                "tags": {
                    "Environment": "dev",
                    "ManagedBy": "Terraform",
                    "Name": "drift-detector-app",
                    "TerraformName": "app",
                },
            },
        }
    }


@pytest.fixture
def live_state():
    return {
        "aws_s3_bucket.app": {
            "type": "aws_s3_bucket",
            "name": "app",
            "provider": "aws",
            "attributes": {
                "bucket": "drift-detector-app-aa3f37b0",
                "region": "eu-north-1",
                "tags": {
                    "Environment": "test",
                    "ManagedBy": "Terraform",
                    "Name": "drift-detector-app",
                    "TerraformName": "app",
                },
            },
        }
    }


@pytest.fixture
def scored_drift():
    return [
        {
            "resource": "aws_s3_bucket.app",
            "resource_type": "s3",
            "environment": "dev",
            "field": "tags.Environment",
            "expected": "dev",
            "live": "test",
            "resource_weight": 1,
            "environment_multiplier": 1,
            "blast_radius": "low",
            "blast_radius_multiplier": 1,
            "score": 1,
            "severity": "LOW",
        }
    ]


def test_no_drift_does_not_call_remediation(
    expected_state,
    live_state,
):
    with (
        patch(
            "scanner.run_scan.read_state",
            return_value={"resources": []},
        ),
        patch(
            "scanner.run_scan.normalise_state",
            return_value=expected_state,
        ),
        patch(
            "scanner.run_scan.scan_aws_resources",
            return_value=live_state,
        ),
        patch(
            "scanner.run_scan.compare_states",
            return_value={},
        ),
        patch(
            "scanner.run_scan.filter_differences",
            return_value={},
        ),
        patch(
            "scanner.run_scan.format_differences",
            return_value=[],
        ),
        patch(
            "scanner.run_scan.score_differences",
            return_value=[],
        ),
        patch(
            "scanner.run_scan.process_drifts",
        ) as mock_process_drifts,
    ):
        run_scan.main([])

        mock_process_drifts.assert_not_called()


def test_dry_run_passes_execute_apply_false(
    expected_state,
    live_state,
    scored_drift,
):
    with (
        patch(
            "scanner.run_scan.read_state",
            return_value={"resources": []},
        ),
        patch(
            "scanner.run_scan.normalise_state",
            return_value=expected_state,
        ),
        patch(
            "scanner.run_scan.scan_aws_resources",
            return_value=live_state,
        ),
        patch(
            "scanner.run_scan.compare_states",
            return_value={"values_changed": {"test": {}}},
        ),
        patch(
            "scanner.run_scan.filter_differences",
            return_value={"values_changed": {"test": {}}},
        ),
        patch(
            "scanner.run_scan.format_differences",
            return_value=[
                {
                    "resource": "aws_s3_bucket.app",
                    "field": "tags.Environment",
                    "expected": "dev",
                    "live": "test",
                    "difference_type": "values_changed",
                }
            ],
        ),
        patch(
            "scanner.run_scan.score_differences",
            return_value=scored_drift,
        ),
        patch(
            "scanner.run_scan.generate_report",
            return_value={"drift_detected": True},
        ),
        patch(
            "scanner.run_scan.build_slack_payload",
            return_value={"text": "Infrastructure drift detected."},
        ),
        patch(
            "scanner.run_scan.process_drifts",
            return_value=[
                {
                    "decision": {
                        "action": "AUTO_FIX",
                    }
                }
            ],
        ) as mock_process_drifts,
        patch(
            "sys.argv",
            ["run_scan", "--dry-run"],
        ),
    ):
        with pytest.raises(SystemExit) as exc_info:
            run_scan.main()

        assert exc_info.value.code == 1

        mock_process_drifts.assert_called_once_with(
            scored_drift,
            state_bucket=run_scan.BUCKET,
            state_key=run_scan.KEY,
            execute_apply=False,
        )


def test_normal_run_passes_execute_apply_true(
    expected_state,
    live_state,
    scored_drift,
):
    with (
        patch(
            "scanner.run_scan.read_state",
            return_value={"resources": []},
        ),
        patch(
            "scanner.run_scan.normalise_state",
            return_value=expected_state,
        ),
        patch(
            "scanner.run_scan.scan_aws_resources",
            return_value=live_state,
        ),
        patch(
            "scanner.run_scan.compare_states",
            return_value={"values_changed": {"test": {}}},
        ),
        patch(
            "scanner.run_scan.filter_differences",
            return_value={"values_changed": {"test": {}}},
        ),
        patch(
            "scanner.run_scan.format_differences",
            return_value=[
                {
                    "resource": "aws_s3_bucket.app",
                    "field": "tags.Environment",
                    "expected": "dev",
                    "live": "test",
                    "difference_type": "values_changed",
                }
            ],
        ),
        patch(
            "scanner.run_scan.score_differences",
            return_value=scored_drift,
        ),
        patch(
            "scanner.run_scan.generate_report",
            return_value={"drift_detected": True},
        ),
        patch(
            "scanner.run_scan.build_slack_payload",
            return_value={"text": "Infrastructure drift detected."},
        ),
        patch(
            "scanner.run_scan.process_drifts",
            return_value=[
                {
                    "decision": {
                        "action": "AUTO_FIX",
                    }
                }
            ],
        ) as mock_process_drifts,
        patch(
            "sys.argv",
            ["run_scan"],
        ),
    ):
        with pytest.raises(SystemExit) as exc_info:
            run_scan.main()

        assert exc_info.value.code == 1

        mock_process_drifts.assert_called_once_with(
            scored_drift,
            state_bucket=run_scan.BUCKET,
            state_key=run_scan.KEY,
            execute_apply=True,
        )


def test_multiple_drifts_are_passed_to_remediation(
    expected_state,
    live_state,
):
    multiple_drifts = [
        {
            "resource": "aws_s3_bucket.app",
            "field": "tags.Environment",
            "score": 1,
            "severity": "LOW",
        },
        {
            "resource": "aws_instance.web",
            "field": "instance_type",
            "score": 14,
            "severity": "MEDIUM",
        },
    ]

    with (
        patch(
            "scanner.run_scan.read_state",
            return_value={"resources": []},
        ),
        patch(
            "scanner.run_scan.normalise_state",
            return_value=expected_state,
        ),
        patch(
            "scanner.run_scan.scan_aws_resources",
            return_value=live_state,
        ),
        patch(
            "scanner.run_scan.compare_states",
            return_value={"values_changed": {"test": {}}},
        ),
        patch(
            "scanner.run_scan.filter_differences",
            return_value={"values_changed": {"test": {}}},
        ),
        patch(
            "scanner.run_scan.format_differences",
            return_value=[
                {
                    "resource": "aws_s3_bucket.app",
                    "field": "tags.Environment",
                    "expected": "dev",
                    "live": "test",
                    "difference_type": "values_changed",
                }
            ],
        ),
        patch(
            "scanner.run_scan.score_differences",
            return_value=multiple_drifts,
        ),
        patch(
            "scanner.run_scan.generate_report",
            return_value={"drift_detected": True},
        ),
        patch(
            "scanner.run_scan.build_slack_payload",
            return_value={"text": "Infrastructure drift detected."},
        ),
        patch(
            "scanner.run_scan.process_drifts",
            return_value=[],
        ) as mock_process_drifts,
        patch(
            "sys.argv",
            ["run_scan", "--dry-run"],
        ),
    ):
        with pytest.raises(SystemExit):
            run_scan.main()

        mock_process_drifts.assert_called_once_with(
            multiple_drifts,
            state_bucket=run_scan.BUCKET,
            state_key=run_scan.KEY,
            execute_apply=False,
        )