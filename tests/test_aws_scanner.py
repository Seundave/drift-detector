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