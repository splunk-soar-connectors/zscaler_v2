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
from typing import Any

from soar_sdk.action_results import ActionOutput, OutputField, PermissiveActionOutput
from soar_sdk.exceptions import ActionFailure
from soar_sdk.logging import getLogger
from soar_sdk.params import Param, Params

from ..asset import Asset
from ..zscaler_client import get_client

logger = getLogger()

_MAX_PAGE_SIZE = 1000


class ListDestinationGroupParams(Params):
    ip_group_ids: str | None = Param(
        description="A comma-separated list of unique identifiers for the IP destination groups",
        primary=True,
    )
    exclude_type: str | None = Param(
        description="The IP group type to be excluded from the results", primary=True
    )
    category_type: str | None = Param(
        description="Comma-separated IP group types to include. This parameter is supported only when 'lite' is true"
    )
    limit: float | None = Param(
        description="Limit of the results to be retrieved", default=50
    )
    lite: bool | None = Param(
        description="Whether to retrieve only limited information of IP destination groups. Includes ID, name and type of the IP destination groups",
        default=False,
    )


class ListDestinationGroupOutput(PermissiveActionOutput):
    id: int | None = OutputField(column_name="Group ID")
    name: str | None = OutputField(column_name="Group Name")
    type: str | None = OutputField(
        column_name="Type",
        example_values=["DSTN_IP", "DSTN_FQDN", "DSTN_DOMAIN", "DSTN_OTHER"],
    )
    addresses: list[str] | None = OutputField(
        column_name="Addresses",
        example_values=["192.168.1.1"],
    )
    countries: list[str] | None = OutputField(column_name="Countries")
    description: str | None = OutputField(column_name="Description")
    ipCategories: list[str] | None = OutputField(
        column_name="IP Categories", example_values=["TRADING_BROKARAGE_INSURANCE"]
    )
    isNonEditable: bool | None = OutputField(column_name="Non-editable")
    creatorContext: str | None = None


class ListDestinationGroupSummary(ActionOutput):
    message: str = OutputField(example_values=["Destination groups retrieved"])


def list_destination_group(
    params: ListDestinationGroupParams, soar: SOARClient, asset: Asset
) -> list[ListDestinationGroupOutput]:
    limit_value = 50 if params.limit is None else params.limit
    if not float(limit_value).is_integer() or limit_value <= 0:
        message = "Limit must be a positive integer."
        soar.set_message(message)
        raise ActionFailure(message)
    limit = int(limit_value)

    group_ids = [
        group_id.strip()
        for group_id in (params.ip_group_ids or "").split(",")
        if group_id.strip()
    ]
    category_types = {
        category_type.strip()
        for category_type in (params.category_type or "").split(",")
        if category_type.strip()
    }

    try:
        raw_groups: list[dict[str, Any]] = []
        with get_client(asset) as client:
            if group_ids:
                for group_id in group_ids:
                    group, response, error = (
                        client.zia.cloud_firewall.get_ip_destination_group(
                            int(group_id)
                        )
                    )
                    if error is not None:
                        raise RuntimeError(f"Zscaler API error: {error}")
                    if group is None or response is None:
                        raise RuntimeError(
                            f"Zscaler API returned no destination group {group_id}"
                        )
                    raw_group = response.get_body()
                    if not isinstance(raw_group, dict):
                        raise RuntimeError(
                            f"Zscaler API returned invalid destination group {group_id}"
                        )
                    raw_groups.append(raw_group)
            else:
                page = 1
                remaining = limit
                while remaining > 0:
                    _groups, response, error = (
                        client.zia.cloud_firewall.list_ip_destination_groups(
                            exclude_type=params.exclude_type,
                            query_params={
                                "page": page,
                                "pageSize": min(remaining, _MAX_PAGE_SIZE),
                            },
                        )
                    )
                    if error is not None:
                        raise RuntimeError(f"Zscaler API error: {error}")
                    if response is None:
                        raise RuntimeError(
                            "Zscaler API returned no destination group response"
                        )
                    page_groups = response.get_results()
                    if not isinstance(page_groups, list):
                        raise RuntimeError(
                            "Zscaler API returned an invalid destination group list"
                        )
                    if not page_groups:
                        break
                    raw_groups.extend(page_groups[:remaining])
                    remaining -= len(page_groups)
                    page += 1

        rows: list[ListDestinationGroupOutput] = []
        for raw_group in raw_groups:
            group_data = dict(raw_group)
            extensions = group_data.pop("extensions", None)
            if isinstance(extensions, dict):
                group_data.update(extensions)

            group_type = group_data.get("type")
            if params.exclude_type and group_type == params.exclude_type:
                continue
            if params.lite and category_types and group_type not in category_types:
                continue
            if params.lite:
                group_data = {
                    key: group_data[key]
                    for key in ("id", "name", "type")
                    if key in group_data
                }
            rows.append(ListDestinationGroupOutput(**group_data))
    except Exception as exc:
        logger.exception("List destination group failed")
        message = f"List destination group failed: {exc}"
        soar.set_message(message)
        raise ActionFailure(message) from exc

    message = "Destination groups retrieved"
    soar.set_summary(ListDestinationGroupSummary(message=message))
    soar.set_message(message)
    return rows
