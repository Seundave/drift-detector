import argparse
import json
import os

from aws_scanner import scan_aws_resources
from differ import compare_states
from normaliser import normalise_state
from state_reader import read_state
from false_positive_filter import filter_differences
from drift_formatter import (
    format_differences,
    print_drift_report,
)

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
        )
    )

    print("\n--- FILTERED DRIFT RESULTS ---")
    print(
        json.dumps(
            filtered_differences,
            indent=2,
        )
    )

    print_drift_report(
        formatted_differences
    )


    if filtered_differences:
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