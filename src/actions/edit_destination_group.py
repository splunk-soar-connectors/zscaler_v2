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


class EditDestinationGroupParams(Params):
    ip_group_id: float = Param(
        description="The unique identifier for the IP destination group", primary=True
    )
    name: str | None = Param(description="Destination IP group name", primary=True)
    addresses: str | None = Param(
        description="Comma-separated destination IP addresses, FQDNs, or wildcard FQDNs to assign to the group"
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
    is_non_editable: bool | None = Param(
        description="If set to true, the destination IP address group is non-editable. This field is applicable only to predefined IP address groups, which cannot be modified",
        default=False,
    )


class EditDestinationGroupOutput(ActionOutput):
    id: float
    name: str
    type: str = OutputField(
        example_values=["DSTN_IP", "DSTN_FQDN", "DSTN_DOMAIN", "DSTN_OTHER"]
    )
    addresses: list[str] = OutputField(example_values=["192.168.1.1"])
    countries: list[str]
    description: str
    ipCategories: list[str] = OutputField(
        example_values=["TRADING_BROKARAGE_INSURANCE"]
    )
    isNonEditable: bool
    creatorContext: str


def edit_destination_group(
    params: EditDestinationGroupParams, soar: SOARClient, asset: Asset
) -> EditDestinationGroupOutput:
    if not params.ip_group_id.is_integer():
        message = "Edit destination group failed: ip_group_id must be an integer"
        soar.set_message(message)
        raise ActionFailure(message)
    if params.ip_group_id <= 0:
        message = "Edit destination group failed: ip_group_id must be positive"
        soar.set_message(message)
        raise ActionFailure(message)

    numeric_group_id = int(params.ip_group_id)
    group_id = str(numeric_group_id)

    try:
        with get_client(asset) as client:
            group, group_response, group_error = (
                client.zia.cloud_firewall.get_ip_destination_group(numeric_group_id)
            )
            if group_error is not None:
                raise RuntimeError(f"Zscaler API error: {group_error}")
            if group is None or group_response is None:
                raise RuntimeError("Zscaler API returned no destination group")

            raw_group = group_response.get_body()
            if not isinstance(raw_group, dict):
                raise RuntimeError("Zscaler API returned an invalid destination group")

            if params.name is not None:
                raw_group["name"] = params.name
            if params.addresses:
                raw_group["addresses"] = [
                    item.strip() for item in params.addresses.split(",") if item.strip()
                ]
            if params.description is not None:
                raw_group["description"] = params.description
            if params.ip_categories:
                raw_group["ipCategories"] = [
                    item.strip()
                    for item in params.ip_categories.split(",")
                    if item.strip()
                ]
            if params.countries:
                raw_group["countries"] = [
                    item.strip() for item in params.countries.split(",") if item.strip()
                ]
            raw_group["isNonEditable"] = params.is_non_editable

            updated, updated_response, update_error = (
                client.zia.cloud_firewall.update_ip_destination_group(
                    group_id,
                    **raw_group,
                )
            )
            if update_error is not None:
                raise RuntimeError(f"Zscaler API error: {update_error}")
            if updated is None or updated_response is None:
                raise RuntimeError("Zscaler API returned no updated destination group")

            raw_updated = updated_response.get_body()
            if not isinstance(raw_updated, dict):
                raise RuntimeError(
                    "Zscaler API returned an invalid updated destination group"
                )

            activation, _response, activation_error = client.zia.activate.activate()
            if activation_error is not None:
                raise RuntimeError(f"Zscaler API error: {activation_error}")
            if activation is None:
                raise RuntimeError("Zscaler API returned no activation response")
    except Exception as exc:
        logger.exception("Edit destination group failed")
        message = f"Edit destination group failed: {exc}"
        soar.set_message(message)
        raise ActionFailure(message) from exc

    soar.set_message("Destination group edited")
    return EditDestinationGroupOutput.model_construct(**raw_updated)
