from scanner.aws_scanner import (
    get_bucket_region,
    get_bucket_tags,
    scan_s3_buckets,
)


class FakeS3Client:
    def list_buckets(self):
        return {
            "Buckets": [
                {"Name": "terraform-app"},
                {"Name": "unmanaged-bucket"},
            ]
        }

    def get_bucket_tagging(self, Bucket):
        if Bucket == "terraform-app":
            return {
                "TagSet": [
                    {
                        "Key": "TerraformName",
                        "Value": "app",
                    },
                    {
                        "Key": "Environment",
                        "Value": "dev",
                    },
                ]
            }

        return {
            "TagSet": []
        }

    def get_bucket_location(self, Bucket):
        return {
            "LocationConstraint": "eu-north-1"
        }


def test_get_bucket_tags():
    s3 = FakeS3Client()

    tags = get_bucket_tags(
        s3,
        "terraform-app",
    )

    assert tags == {
        "TerraformName": "app",
        "Environment": "dev",
    }


def test_get_bucket_region():
    s3 = FakeS3Client()

    region = get_bucket_region(
        s3,
        "terraform-app",
    )

    assert region == "eu-north-1"


def test_scan_s3_buckets_only_returns_terraform_resources(
    monkeypatch,
):
    fake_s3 = FakeS3Client()

    monkeypatch.setattr(
        "scanner.aws_scanner.boto3.client",
        lambda service: fake_s3,
    )

    result = scan_s3_buckets()

    assert result == {
        "aws_s3_bucket.app": {
            "type": "aws_s3_bucket",
            "name": "app",
            "provider": "aws",
            "attributes": {
                "bucket": "terraform-app",
                "region": "eu-north-1",
                "tags": {
                    "TerraformName": "app",
                    "Environment": "dev",
                },
            },
        }
    }


def test_get_bucket_tags_returns_empty_dict_when_bucket_has_no_tags(
    monkeypatch,
):
    class NoTagsS3Client:
        def get_bucket_tagging(self, Bucket):
            from botocore.exceptions import ClientError

            raise ClientError(
                {
                    "Error": {
                        "Code": "NoSuchTagSet",
                        "Message": "The specified bucket has no tags.",
                    }
                },
                "GetBucketTagging",
            )

    s3 = NoTagsS3Client()

    tags = get_bucket_tags(
        s3,
        "untagged-bucket",
    )

    assert tags == {}


def test_get_bucket_tags_reraises_unexpected_errors():
    from botocore.exceptions import ClientError

    class FailingS3Client:
        def get_bucket_tagging(self, Bucket):
            raise ClientError(
                {
                    "Error": {
                        "Code": "AccessDenied",
                        "Message": "Access denied.",
                    }
                },
                "GetBucketTagging",
            )

    s3 = FailingS3Client()

    try:
        get_bucket_tags(
            s3,
            "restricted-bucket",
        )
    except ClientError as error:
        assert error.response["Error"]["Code"] == "AccessDenied"
    else:
        raise AssertionError(
            "Expected AccessDenied error to be raised"
        )


def test_scan_ec2_instances(monkeypatch):
    class FakeEC2:
        def describe_instances(self):
            return {
                "Reservations": [
                    {
                        "Instances": [
                            {
                                "InstanceId": "i-123456",
                                "InstanceType": "t3.micro",
                                "ImageId": "ami-123456",
                                "Placement": {
                                    "AvailabilityZone": "eu-north-1a"
                                },
                                "SubnetId": "subnet-123",
                                "VpcId": "vpc-123",
                                "SecurityGroups": [
                                    {
                                        "GroupId": "sg-123"
                                    }
                                ],
                                "State": {
                                    "Name": "running"
                                },
                                "Tags": [
                                    {
                                        "Key": "TerraformName",
                                        "Value": "web",
                                    },
                                    {
                                        "Key": "Environment",
                                        "Value": "dev",
                                    },
                                ],
                            }
                        ]
                    }
                ]
            }

    def fake_client(service_name):
        assert service_name == "ec2"
        return FakeEC2()

    monkeypatch.setattr(
        "boto3.client",
        fake_client,
    )

    from scanner.aws_scanner import scan_ec2_instances

    result = scan_ec2_instances()

    assert "aws_instance.web" in result

    instance = result["aws_instance.web"]

    assert instance["type"] == "aws_instance"
    assert instance["attributes"]["instance_type"] == "t3.micro"
    assert instance["attributes"]["ami"] == "ami-123456"
    # assert instance["attributes"]["vpc_id"] == "vpc-123"
    assert instance["attributes"]["state"] == "running"



def test_scan_security_groups(monkeypatch):
    class FakeEC2:
        def describe_security_groups(self):
            return {
                "SecurityGroups": [
                    {
                        "GroupId": "sg-123456",
                        "GroupName": "drift-detector-web",
                        "Description": "Web security group",
                        "VpcId": "vpc-123456",
                        "Tags": [
                            {
                                "Key": "TerraformName",
                                "Value": "web",
                            },
                            {
                                "Key": "Environment",
                                "Value": "dev",
                            },
                        ],
                        "IpPermissions": [
                            {
                                "IpProtocol": "tcp",
                                "FromPort": 80,
                                "ToPort": 80,
                                "IpRanges": [
                                    {
                                        "CidrIp": "0.0.0.0/0"
                                    }
                                ],
                                "Ipv6Ranges": [],
                                "UserIdGroupPairs": [],
                            }
                        ],
                        "IpPermissionsEgress": [
                            {
                                "IpProtocol": "-1",
                                "FromPort": 0,
                                "ToPort": 0,
                                "IpRanges": [
                                    {
                                        "CidrIp": "0.0.0.0/0"
                                    }
                                ],
                                "Ipv6Ranges": [],
                                "UserIdGroupPairs": [],
                            }
                        ],
                    }
                ]
            }

    def fake_client(service_name):
        assert service_name == "ec2"
        return FakeEC2()

    monkeypatch.setattr(
        "boto3.client",
        fake_client,
    )

    from scanner.aws_scanner import scan_security_groups

    result = scan_security_groups()

    assert "aws_security_group.web" in result

    security_group = result[
        "aws_security_group.web"
    ]

    assert (
        security_group["type"]
        == "aws_security_group"
    )

    assert (
        security_group["attributes"]["group_id"]
        == "sg-123456"
    )

    assert (
        security_group["attributes"]["vpc_id"]
        == "vpc-123456"
    )

    assert (
        security_group["attributes"]["ingress"][0][
            "from_port"
        ]
        == 80
    )