from typing import Any, Dict


def _normalise_s3_bucket(raw_attributes: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "bucket": raw_attributes.get("bucket") or raw_attributes.get("id"),
        "region": raw_attributes.get("region") or "eu-north-1",
        "tags": raw_attributes.get("tags") or {},
    }


def _normalise_ec2_instance(raw_attributes: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "instance_id": raw_attributes.get("id"),
        "instance_type": raw_attributes.get("instance_type"),
        "ami": raw_attributes.get("ami"),
        "availability_zone": raw_attributes.get("availability_zone"),
        "subnet_id": raw_attributes.get("subnet_id"),
        # "vpc_id": raw_attributes.get("vpc_id"),
        "security_groups": raw_attributes.get("vpc_security_group_ids")
        or raw_attributes.get("security_groups")
        or [],
        "state": raw_attributes.get("instance_state", "running"),
        "tags": raw_attributes.get("tags") or {},
    }


def _normalise_sg_rule(rule: Dict[str, Any]) -> Dict[str, Any]:
    from_port = rule.get("from_port")
    to_port = rule.get("to_port")

    # AWS API returns null/None for wildcards (protocol "-1" / "all")
    if rule.get("protocol") == "-1" and (from_port == 0 or from_port is None):
        from_port = None
        to_port = None

    return {
        "protocol": rule.get("protocol"),
        "from_port": from_port,
        "to_port": to_port,
        "cidr_blocks": rule.get("cidr_blocks") or [],
        "ipv6_cidr_blocks": rule.get("ipv6_cidr_blocks") or [],
        "security_group_ids": rule.get("security_groups") or [],
    }


def _normalise_security_group(raw_attributes: Dict[str, Any]) -> Dict[str, Any]:
    ingress_rules = [
        _normalise_sg_rule(rule) for rule in raw_attributes.get("ingress", [])
    ]
    egress_rules = [
        _normalise_sg_rule(rule) for rule in raw_attributes.get("egress", [])
    ]

    return {
        "group_id": raw_attributes.get("id"),
        "name": raw_attributes.get("name"),
        "description": raw_attributes.get("description"),
        "vpc_id": raw_attributes.get("vpc_id"),
        "ingress": ingress_rules,
        "egress": egress_rules,
        "tags": raw_attributes.get("tags") or {},
    }


def normalise_state(
    state: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    """
    Convert raw Terraform state into a normalized resource dictionary.
    """

    normalized_resources: dict[str, dict[str, Any]] = {}
    resources = state.get("resources", [])

    for resource in resources:
        if resource.get("mode") != "managed":
            continue

        resource_type = resource.get("type")
        resource_name = resource.get("name")
        provider = resource.get("provider", "")

        if not resource_type or not resource_name:
            continue

        address = f"{resource_type}.{resource_name}"
        provider_name = provider.rsplit("/", 1)[-1].rstrip('"]')
        instances = resource.get("instances", [])

        for index, instance in enumerate(instances):
            raw_attributes = instance.get("attributes", {})

            # Filter resource attributes down to target comparison keys
            if resource_type == "aws_s3_bucket":
                attributes = _normalise_s3_bucket(raw_attributes)
            elif resource_type == "aws_instance":
                attributes = _normalise_ec2_instance(raw_attributes)
            elif resource_type == "aws_security_group":
                attributes = _normalise_security_group(raw_attributes)
            else:
                attributes = raw_attributes

            resource_key = address
            if len(instances) > 1:
                resource_key = f"{address}[{index}]"

            normalized_resources[resource_key] = {
                "type": resource_type,
                "name": resource_name,
                "provider": provider_name,
                "attributes": attributes,
            }

    return normalized_resources


if __name__ == "__main__":
    import json
    from pathlib import Path

    state_file = Path("terraform-lab/terraform.tfstate")

    with state_file.open("r", encoding="utf-8") as file:
        state = json.load(file)

    normalized_state = normalise_state(state)

    print(json.dumps(normalized_state, indent=2))