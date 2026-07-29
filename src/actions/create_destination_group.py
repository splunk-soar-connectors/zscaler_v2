# Copyright (c) 2026 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import OutputField, PermissiveActionOutput
from soar_sdk.exceptions import ActionFailure
from soar_sdk.logging import getLogger
from soar_sdk.params import Param, Params

from ..asset import Asset
from ..zscaler_client import get_client

logger = getLogger()

SUPPORTED_DESTINATION_GROUP_TYPES = {
    "DSTN_DOMAIN",
    "DSTN_FQDN",
    "DSTN_IP",
    "DSTN_OTHER",
}


def _comma_separated_values(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


class CreateDestinationGroupParams(Params):
    name: str = Param(description="Destination group name", primary=True)
    type: str = Param(
        description=(
            "Destination group type. Supported values: DSTN_IP, DSTN_FQDN, "
            "DSTN_DOMAIN, and DSTN_OTHER"
        ),
        primary=True,
        value_list=sorted(SUPPORTED_DESTINATION_GROUP_TYPES),
    )
    addresses: str | None = Param(
        description="Comma-separated destination IP addresses, FQDNs, or wildcard FQDNs to add to the group"
    )
    description: str | None = Param(
        description="Additional information about the destination group."
    )
    ip_categories: str | None = Param(
        description="Destination IP address URL categories"
    )
    countries: str | None = Param(
        description="Destination IP address countries. You can identify destinations based on the location of a server."
    )


class CreateDestinationGroupOutput(PermissiveActionOutput):
    id: int | None = OutputField()
    name: str | None = OutputField()
    type: str | None = OutputField(
        example_values=["DSTN_IP", "DSTN_FQDN", "DSTN_DOMAIN", "DSTN_OTHER"],
    )
    addresses: list[str] | None = OutputField(example_values=["192.168.1.1"])
    countries: list[str] | None = OutputField()
    description: str | None = OutputField()
    ipCategories: list[str] | None = OutputField(
        example_values=["TRADING_BROKARAGE_INSURANCE"]
    )
    isNonEditable: bool | None = OutputField()
    creatorContext: str | None = OutputField()


def create_destination_group(
    params: CreateDestinationGroupParams, soar: SOARClient, asset: Asset
) -> CreateDestinationGroupOutput:
    if params.type not in SUPPORTED_DESTINATION_GROUP_TYPES:
        supported = ", ".join(sorted(SUPPORTED_DESTINATION_GROUP_TYPES))
        message = f"Create destination group failed: type must be one of {supported}"
        soar.set_message(message)
        raise ActionFailure(message)

    data: dict[str, str | list[str]] = {
        "name": params.name,
        "type": params.type,
        "description": params.description or "",
    }
    if params.addresses:
        data["addresses"] = _comma_separated_values(params.addresses)
    if params.ip_categories:
        data["ipCategories"] = _comma_separated_values(params.ip_categories)
    if params.countries:
        data["countries"] = _comma_separated_values(params.countries)

    try:
        with get_client(asset) as client:
            created, response, error = (
                client.zia.cloud_firewall.add_ip_destination_group(**data)
            )
            if error is not None:
                raise RuntimeError(f"Zscaler API error: {error}")
            if created is None or response is None:
                raise RuntimeError("Zscaler API returned no destination group")

            raw_created = response.get_body()
            if not isinstance(raw_created, dict):
                raise RuntimeError("Zscaler API returned an invalid destination group")

            activation, _response, activation_error = client.zia.activate.activate()
            if activation_error is not None or activation is None:
                detail = activation_error or "Zscaler API returned no activation data"
                raise RuntimeError(
                    "The destination group was created but could not be activated and "
                    f"is not yet enforced. {detail}"
                )
    except Exception as exc:
        logger.exception("Create destination group failed")
        message = f"Create destination group failed: {exc}"
        soar.set_message(message)
        raise ActionFailure(message) from exc

    soar.set_message("Destination group created")
    return CreateDestinationGroupOutput(**raw_created)
