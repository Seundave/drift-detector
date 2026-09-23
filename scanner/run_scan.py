import argparse
import json
import os

from scanner.aws_scanner import scan_aws_resources
from scanner.differ import compare_states
from scanner.drift_formatter import (
    format_differences,
    print_drift_report,
)
from scanner.false_positive_filter import filter_differences
from scanner.normaliser import normalise_state
from scanner.state_reader import read_state
from scorer.report_generator import (
    build_slack_payload,
    generate_report,
)
from scorer.scorer import score_drift

os.environ["TF_STATE_BUCKET"] = "drift-detector-tfstate-aa3f37b0"

BUCKET = os.environ["TF_STATE_BUCKET"]
KEY = os.getenv(
    "TF_STATE_KEY",
    "drift-detector/terraform.tfstate",
)

def parse_args() -> argparse.Namespace:
    """
    Parse command-line arguments.
    """
    parser = argparse.ArgumentParser(
        description="Detect infrastructure drift."
    )

    parser.add_argument(
        "--dry-run",
        action="store_true",
        help=(
            "Detect and report drift without "
            "performing remediation."
        ),
    )

    return parser.parse_args()


def get_resource_attributes(
    resource: str,
    expected_state: dict,
    live_state: dict,
) -> dict:
    """
    Get resource attributes for severity scoring.

    Expected Terraform state is preferred because it
    represents the intended configuration.

    Live state is used as a fallback for resources
    that exist only in the live environment.
    """

    expected_resource = expected_state.get(
        resource,
        {},
    )

    expected_attributes = (
        expected_resource.get(
            "attributes",
            {},
        )
    )

    if expected_attributes:
        return expected_attributes

    live_resource = live_state.get(
        resource,
        {},
    )

    return live_resource.get(
        "attributes",
        {},
    )


def score_differences(
    formatted_differences: list[dict],
    expected_state: dict,
    live_state: dict,
) -> list[dict]:
    """
    Add severity scoring information to every
    formatted drift item.
    """

    scored_drifts = []

    for drift in formatted_differences:
        resource = drift["resource"]

        attributes = get_resource_attributes(
            resource=resource,
            expected_state=expected_state,
            live_state=live_state,
        )

        scored_drift = score_drift(
            drift=drift,
            attributes=attributes,
        )

        scored_drifts.append(
            scored_drift
        )

    return scored_drifts


def main() -> None:
    args = parse_args()

    if args.dry_run:
        print("\nDRY RUN MODE ENABLED")
        print(
            "No infrastructure changes will be made."
        )

    print("\nReading Terraform state...")

    terraform_state = read_state(
        bucket=BUCKET,
        key=KEY,
    )

    expected_state = normalise_state(
        terraform_state
    )

    print("\n--- EXPECTED TERRAFORM STATE ---")
    print(
        json.dumps(
            expected_state,
            indent=2,
        )
    )

    print("\nScanning live AWS state...")

    live_state = scan_aws_resources()

    print("\n--- NORMALIZED LIVE AWS STATE ---")
    print(
        json.dumps(
            live_state,
            indent=2,
        )
    )

    print("\nComparing states...")

    differences = compare_states(
        expected_state,
        live_state,
    )

    filtered_differences = filter_differences(
        differences
    )

    formatted_differences = format_differences(
        filtered_differences
    )


    print("\n--- RAW DRIFT RESULTS ---")
    print(
        json.dumps(
            differences,
            indent=2,
            default=str,
        )
    )

    print("\n--- FILTERED DRIFT RESULTS ---")
    print(
        json.dumps(
            filtered_differences,
            indent=2,
            default=str,
        )
    )

    print("\n--- FORMATTED DRIFT ---")

    print_drift_report(
        formatted_differences
    )

    print("\nScoring detected drift...")

    scored_drifts = score_differences(
        formatted_differences=formatted_differences,
        expected_state=expected_state,
        live_state=live_state,
    )

    print("\n--- SCORED DRIFT ---")

    print(
        json.dumps(
            scored_drifts,
            indent=2,
            default=str,
        )
    )

    report = generate_report(
        scored_drifts
    )

    slack_payload = build_slack_payload(
        scored_drifts
    )

    print("\n--- DRIFT REPORT ---")

    print(
        json.dumps(
            report,
            indent=2,
            default=str,
        )
    )

    print("\n--- SLACK PAYLOAD PREVIEW ---")

    print(
        json.dumps(
            slack_payload,
            indent=2,
            default=str,
        )
    )

    if scored_drifts:
        print("\nREAL DRIFT DETECTED")

        if args.dry_run:
            print(
                "DRY RUN: no remediation was performed."
            )
        else:
            print(
                "No remediation is currently "
                "configured."
            )

        raise SystemExit(1)

    print("\nNO ACTIONABLE DRIFT DETECTED")


if __name__ == "__main__":
    main()