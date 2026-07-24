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
from soar_sdk.action_results import ActionOutput, OutputField
from soar_sdk.exceptions import ActionFailure
from soar_sdk.logging import getLogger
from soar_sdk.params import Param, Params

from ..asset import Asset
from ..zscaler_client import get_client

logger = getLogger()


class CreateDestinationGroupParams(Params):
    name: str = Param(description="Destination IP group name", primary=True)
    type: str = Param(
        description="Destination IP group type (i.e., the group can contain destination IP addresses, countries, URL categories or FQDNs)",
        primary=True,
    )
    addresses: str | None = Param(
        description="Comma seperated string of destination IP addresses, FQDNs, or wildcard FQDNs added to the group"
    )
    description: str | None = Param(
        description="Additional information about the destination IP group."
    )
    ip_categories: str | None = Param(
        description="Destination IP address URL categories"
    )
    countries: str | None = Param(
        description="Destination IP address countries. You can identify destinations based on the location of a server."
    )


class CreateDestinationGroupOutput(ActionOutput):
    id: float
    name: str
    type: str = OutputField(
        example_values=["DSTN_IP", "DSTN_FQDN", "DSTN_DOMAIN", "DSTN_OTHER"]
    )
    addresses: str = OutputField(example_values=["192.168.1.1"])
    countries: str
    description: str
    ipCategories: str = OutputField(example_values=["TRADING_BROKARAGE_INSURANCE"])
    isNonEditable: bool
    creatorContext: str


class CreateDestinationGroupSummary(ActionOutput):
    message: str = OutputField(example_values=["Destination Group Created"])


def create_destination_group(
    params: CreateDestinationGroupParams, soar: SOARClient, asset: Asset
) -> CreateDestinationGroupOutput:
    data: dict[str, str | list[str]] = {
        "name": params.name,
        "type": params.type,
        "description": params.description or "",
    }
    if params.addresses:
        data["addresses"] = [item.strip() for item in params.addresses.split(",")]
    if params.ip_categories:
        data["ipCategories"] = [
            item.strip() for item in params.ip_categories.split(",")
        ]
    if params.countries:
        data["countries"] = [item.strip() for item in params.countries.split(",")]

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
            if activation_error is not None:
                raise RuntimeError(f"Zscaler API error: {activation_error}")
            if activation is None:
                raise RuntimeError("Zscaler API returned no activation response")
    except Exception as exc:
        logger.exception("Create destination group failed")
        message = f"Create destination group failed: {exc}"
        soar.set_message(message)
        raise ActionFailure(message) from exc

    soar.set_summary(CreateDestinationGroupSummary(message="Destination Group Created"))
    return CreateDestinationGroupOutput.model_construct(**raw_created)
