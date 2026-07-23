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
from typing import Any

from pydantic import Field
from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput, OutputField
from soar_sdk.exceptions import ActionFailure
from soar_sdk.logging import getLogger
from soar_sdk.params import Param, Params

from ..asset import Asset
from ..zscaler_client import get_client

logger = getLogger()

_MAX_PAGE_SIZE = 1000


class GetGroupsParams(Params):
    search: str | None = Param(
        description="The search string used to match against a group's name or comments attributes"
    )
    limit: float | None = Param(
        description="Maximum number of records to fetch", default=1000
    )


class GetGroupsOutput(ActionOutput):
    comments: str = Field(json_schema_extra={"examples": ["test This is for testing"]})
    id: int = OutputField(
        cef_types=["zscaler group id"],
        column_name="ID",
        example_values=[8894813],
    )
    isNonEditable: bool = Field(json_schema_extra={"examples": [True]})
    name: str = OutputField(
        column_name="Group Name",
        example_values=["test Frothly Internet Access"],
    )


class GetGroupsSummary(ActionOutput):
    total_groups: int = OutputField(example_values=[4])


def get_groups(
    params: GetGroupsParams, soar: SOARClient, asset: Asset
) -> list[GetGroupsOutput]:
    if (
        params.limit is None
        or not float(params.limit).is_integer()
        or params.limit <= 0
    ):
        message = "Limit must be a positive integer."
        soar.set_message(message)
        raise ActionFailure(message)
    limit = int(params.limit)

    try:
        raw_groups: list[dict[str, Any]] = []
        page = 1
        remaining = limit
        with get_client(asset) as client:
            while remaining > 0:
                query_params: dict[str, str | int] = {
                    "page": page,
                    "page_size": min(remaining, _MAX_PAGE_SIZE),
                }
                if params.search:
                    query_params["search"] = params.search

                _groups, response, error = client.zia.user_management.list_groups(
                    query_params
                )
                if error is not None:
                    raise RuntimeError(f"Zscaler API error: {error}")
                if response is None:
                    raise RuntimeError("Zscaler API returned no groups response")

                page_groups = response.get_results()
                if not isinstance(page_groups, list):
                    raise RuntimeError("Zscaler API returned an invalid groups list")
                if not page_groups:
                    break

                for group in page_groups:
                    if not isinstance(group, dict):
                        raise RuntimeError(
                            "Zscaler API returned an invalid group record"
                        )
                    raw_groups.append(group)

                remaining -= len(page_groups)
                page += 1

        rows: list[GetGroupsOutput] = []
        for group in raw_groups[:limit]:
            if not isinstance(group.get("id"), int) or not isinstance(
                group.get("name"), str
            ):
                raise RuntimeError("Zscaler API returned an invalid group record")
            if "comments" in group and not isinstance(group["comments"], str):
                raise RuntimeError("Zscaler API returned an invalid group record")
            if "isNonEditable" in group and not isinstance(
                group["isNonEditable"], bool
            ):
                raise RuntimeError("Zscaler API returned an invalid group record")
            rows.append(GetGroupsOutput.model_construct(**group))
    except Exception as exc:
        logger.exception("Get groups failed")
        message = f"Get groups failed: {exc}"
        soar.set_message(message)
        raise ActionFailure(message) from exc

    soar.set_summary(GetGroupsSummary(total_groups=len(rows)))
    return rows
