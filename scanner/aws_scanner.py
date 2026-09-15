import json
from typing import Any

import boto3


def scan_s3_buckets() -> dict[str, dict[str, Any]]:
    """
    Scan S3 buckets in the AWS account and return them
    in the normalized resource format.
    """

    s3 = boto3.client("s3")

    response = s3.list_buckets()

    # Pretty print raw boto3 response for list_buckets
    print("--- RAW S3 LIST_BUCKETS RESPONSE ---")
    print(json.dumps(response, indent=2, default=str))
    print("------------------------------------\n")

    resources: dict[str, dict[str, Any]] = {}

    for bucket in response.get("Buckets", []):
        bucket_name = bucket["Name"]

        # Handle buckets with no tags gracefully to avoid ClientError crashes
        try:
            tags_response = s3.get_bucket_tagging(Bucket=bucket_name)
            
            tags = {
                tag["Key"]: tag["Value"]
                for tag in tags_response.get("TagSet", [])
            }
            print("---  Tags response---")
            print(json.dumps(tags, indent=2, default=str))
        except s3.exceptions.ClientError:
            tags = {}

        resource_name = tags.get("TerraformName")

        if not resource_name:
            continue

        location_response = s3.get_bucket_location(
            Bucket=bucket_name
        )

        region = location_response.get("LocationConstraint")

        if region is None:
            region = "us-east-1"

        address = f"aws_s3_bucket.{resource_name}"

        resources[address] = {
            "type": "aws_s3_bucket",
            "name": resource_name,
            "provider": "aws",
            "attributes": {
                "bucket": bucket_name,
                "tags": tags,
                "region": region,
            },
        }

    return resources


if __name__ == "__main__":
    # Call function and print the normalized resources dictionary
    scanned_resources = scan_s3_buckets()
    
    print("--- NORMALIZED LIVE AWS RESOURCES ---")
    print(json.dumps(scanned_resources, indent=2))