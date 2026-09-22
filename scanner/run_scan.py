import json
import os

from aws_scanner import scan_aws_resources
from differ import compare_states
from normaliser import normalise_state
from state_reader import read_state
from false_positive_filter import filter_differences

os.environ["TF_STATE_BUCKET"] = "drift-detector-tfstate-aa3f37b0"

BUCKET = os.environ["TF_STATE_BUCKET"]
KEY = os.getenv(
    "TF_STATE_KEY",
    "drift-detector/terraform.tfstate",
)


def main() -> None:
    print("Reading Terraform state...")

    terraform_state = read_state(
        bucket=BUCKET,
        key=KEY,
    )

    expected_state = normalise_state(terraform_state)

    print("\n--- EXPECTED TERRAFORM STATE ---")
    print(json.dumps(expected_state, indent=2))

    print("\nScanning live AWS state...")

    live_state = scan_aws_resources()

    print("\n--- NORMALIZED LIVE AWS STATE ---")
    print(json.dumps(live_state, indent=2))

    print("\nComparing states...")

    differences = compare_states(
        expected_state,
        live_state,
    )
    filtered_differences = filter_differences(differences)

    print("\n--- DRIFT RESULTS ---")
    print(json.dumps(filtered_differences, indent=2, default=str))

    if filtered_differences:
        print("\nDRIFT DETECTED")
        raise SystemExit(1)
    else:
        print("\nNO DRIFT DETECTED")


if __name__ == "__main__":
    main()