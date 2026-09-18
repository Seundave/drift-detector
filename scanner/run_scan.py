import json

from aws_scanner import scan_s3_buckets
from differ import compare_states
from normaliser import normalise_state
from state_reader import read_state
from false_positive_filter import filter_differences


BUCKET = "drift-detector-tfstate-aa3f37b0"
KEY = "drift-detector/terraform.tfstate"


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

    live_state = scan_s3_buckets()

    print("\n--- NORMALIZED LIVE AWS STATE ---")
    print(json.dumps(live_state, indent=2))

    print("\nComparing states...")

    differences = compare_states(
        expected_state,
        live_state,
    )
    filtered_differences = filter_differences(differences)

    print("\n--- DRIFT RESULTS ---")
    print(json.dumps(filtered_differences, indent=2))

    if filtered_differences:
        print("\nDRIFT DETECTED")
    else:
        print("\nNO DRIFT DETECTED")


if __name__ == "__main__":
    main()