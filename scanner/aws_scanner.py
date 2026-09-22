from typing import Any

import boto3
from botocore.exceptions import ClientError


def get_bucket_tags(
    s3: Any,
    bucket_name: str,
) -> dict[str, str]:
    """
    Get tags for an S3 bucket.

    Returns an empty dictionary when the bucket has no tags.
    """

    try:
        response = s3.get_bucket_tagging(
            Bucket=bucket_name
        )

    except ClientError as error:
        error_code = error.response.get("Error", {}).get("Code")

        if error_code == "NoSuchTagSet":
            return {}

        raise

    return {
        tag["Key"]: tag["Value"]
        for tag in response.get("TagSet", [])
    }


def get_bucket_region(
    s3: Any,
    bucket_name: str,
) -> str:
    """
    Get the AWS region where an S3 bucket is located.
    """

    response = s3.get_bucket_location(
        Bucket=bucket_name
    )

    region = response.get("LocationConstraint")

    if region is None:
        return "us-east-1"

    # AWS historically returns this value for buckets in us-east-1.
    if region == "EU":
        return "eu-west-1"

    return region


def scan_s3_buckets() -> dict[str, dict[str, Any]]:
    """
    Scan S3 buckets in the AWS account and return them
    in the normalized resource format.

    Only buckets containing the TerraformName tag are
    considered Terraform-managed resources.
    """

    s3 = boto3.client("s3")

    response = s3.list_buckets()

    resources: dict[str, dict[str, Any]] = {}

    for bucket in response.get("Buckets", []):
        bucket_name = bucket["Name"]

        tags = get_bucket_tags(
            s3,
            bucket_name,
        )

        resource_name = tags.get("TerraformName")

        if not resource_name:
            continue

        region = get_bucket_region(
            s3,
            bucket_name,
        )

        address = f"aws_s3_bucket.{resource_name}"

        resources[address] = {
            "type": "aws_s3_bucket",
            "name": resource_name,
            "provider": "aws",
            "attributes": {
                "bucket": bucket_name,
                "region": region,
                "tags": tags,
            },
        }

    return resources


def scan_ec2_instances() -> dict[str, dict[str, Any]]:
    """
    Scan EC2 instances in the AWS account and return them
    in the normalized resource format.

    Only instances containing the TerraformName tag are
    considered Terraform-managed resources.
    """
    ec2 = boto3.client("ec2")

    response = ec2.describe_instances()

    resources: dict[str, dict[str, Any]] = {}

    for reservation in response.get("Reservations", []):
        for instance in reservation.get("Instances", []):
            tags = {
                tag["Key"]: tag["Value"]
                for tag in instance.get("Tags", [])
            }

            resource_name = tags.get("TerraformName")

            if not resource_name:
                continue

            instance_id = instance["InstanceId"]

            address = f"aws_instance.{resource_name}"

            security_groups = [
                group["GroupId"]
                for group in instance.get(
                    "SecurityGroups",
                    [],
                )
            ]

            resources[address] = {
                "type": "aws_instance",
                "name": resource_name,
                "provider": "aws",
                "attributes": {
                    "instance_id": instance_id,
                    "instance_type": instance.get(
                        "InstanceType"
                    ),
                    "ami": instance.get(
                        "ImageId"
                    ),
                    "availability_zone": instance.get(
                        "Placement",
                        {},
                    ).get("AvailabilityZone"),
                    "subnet_id": instance.get(
                        "SubnetId"
                    ),
                    "vpc_id": instance.get(
                        "VpcId"
                    ),
                    "security_groups": security_groups,
                    "state": instance.get(
                        "State",
                        {},
                    ).get("Name"),
                    "tags": tags,
                },
            }

    return resources


def scan_security_groups() -> dict[str, dict[str, Any]]:
    """
    Scan security groups in the AWS account and return them
    in the normalized resource format.

    Only security groups containing the TerraformName tag
    are considered Terraform-managed resources.
    """
    ec2 = boto3.client("ec2")

    response = ec2.describe_security_groups()

    resources: dict[str, dict[str, Any]] = {}

    for security_group in response.get(
        "SecurityGroups",
        [],
    ):
        tags = {
            tag["Key"]: tag["Value"]
            for tag in security_group.get("Tags", [])
        }

        resource_name = tags.get("TerraformName")

        if not resource_name:
            continue

        address = f"aws_security_group.{resource_name}"

        ingress_rules = []

        for permission in security_group.get(
            "IpPermissions",
            [],
        ):
            ingress_rules.append(
                {
                    "protocol": permission.get("IpProtocol"),
                    "from_port": permission.get("FromPort"),
                    "to_port": permission.get("ToPort"),
                    "cidr_blocks": sorted(
                        [
                            item["CidrIp"]
                            for item in permission.get(
                                "IpRanges",
                                [],
                            )
                        ]
                    ),
                    "ipv6_cidr_blocks": sorted(
                        [
                            item["CidrIpv6"]
                            for item in permission.get(
                                "Ipv6Ranges",
                                [],
                            )
                        ]
                    ),
                    "security_group_ids": sorted(
                        [
                            item["GroupId"]
                            for item in permission.get(
                                "UserIdGroupPairs",
                                [],
                            )
                            if item.get("GroupId")
                        ]
                    ),
                }
            )

        egress_rules = []

        for permission in security_group.get(
            "IpPermissionsEgress",
            [],
        ):
            egress_rules.append(
                {
                    "protocol": permission.get("IpProtocol"),
                    "from_port": permission.get("FromPort"),
                    "to_port": permission.get("ToPort"),
                    "cidr_blocks": sorted(
                        [
                            item["CidrIp"]
                            for item in permission.get(
                                "IpRanges",
                                [],
                            )
                        ]
                    ),
                    "ipv6_cidr_blocks": sorted(
                        [
                            item["CidrIpv6"]
                            for item in permission.get(
                                "Ipv6Ranges",
                                [],
                            )
                        ]
                    ),
                    "security_group_ids": sorted(
                        [
                            item["GroupId"]
                            for item in permission.get(
                                "UserIdGroupPairs",
                                [],
                            )
                            if item.get("GroupId")
                        ]
                    ),
                }
            )

        resources[address] = {
            "type": "aws_security_group",
            "name": resource_name,
            "provider": "aws",
            "attributes": {
                "group_id": security_group.get(
                    "GroupId"
                ),
                "name": security_group.get(
                    "GroupName"
                ),
                "description": security_group.get(
                    "Description"
                ),
                "vpc_id": security_group.get(
                    "VpcId"
                ),
                "ingress": ingress_rules,
                "egress": egress_rules,
                "tags": tags,
            },
        }

    return resources


def scan_aws_resources() -> dict[str, dict[str, Any]]:
    """
    Scan all supported AWS resources and return a single
    normalized live-state dictionary.
    """
    resources: dict[str, dict[str, Any]] = {}

    resources.update(
        scan_s3_buckets()
    )

    resources.update(
        scan_ec2_instances()
    )

    resources.update(
        scan_security_groups()
    )

    return resources


if __name__ == "__main__":
    import json

    live_state = scan_aws_resources()

    print(json.dumps(live_state, indent=2))