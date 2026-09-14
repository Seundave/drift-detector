from typing import Any


def normalise_state(
    state: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    """
    Convert raw Terraform state into a normalized resource dictionary.

    Each managed Terraform resource is keyed by its resource address,
    for example: aws_s3_bucket.app
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
            attributes = instance.get("attributes", {})

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