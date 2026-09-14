import json
from typing import Any

import boto3


def read_state(bucket: str, key: str) -> dict[str, Any]:
    """Read and parse a Terraform state file from S3."""

    s3 = boto3.client("s3")

    response = s3.get_object(
        Bucket=bucket,
        Key=key,
    )

    state_content = response["Body"].read()

    return json.loads(state_content)


def print_managed_resources(state: dict[str, Any]) -> None:
    """Print managed Terraform resources and their attributes."""

    resources = state.get("resources", [])

    for resource in resources:
        if resource.get("mode") != "managed":
            continue

        resource_type = resource.get("type")
        resource_name = resource.get("name")
        address = f"{resource_type}.{resource_name}"

        print(f"\nResource: {address}")
        print("-" * 60)

        instances = resource.get("instances", [])

        for index, instance in enumerate(instances):
            print(f"Instance: {index}")
            print(
                json.dumps(
                    instance.get("attributes", {}),
                    indent=2,
                )
            )


if __name__ == "__main__":
    BUCKET = "drift-detector-tfstate-aa3f37b0"
    KEY = "drift-detector/terraform.tfstate"

    state = read_state(
        bucket=BUCKET,
        key=KEY,
    )

    print_managed_resources(state)