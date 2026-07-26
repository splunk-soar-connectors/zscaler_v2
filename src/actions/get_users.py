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

from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput, OutputField, PermissiveActionOutput
from soar_sdk.exceptions import ActionFailure
from soar_sdk.logging import getLogger
from soar_sdk.params import Param, Params

from ..asset import Asset
from ..zscaler_client import get_client

logger = getLogger()

_MAX_PAGE_SIZE = 1000


class GetUsersParams(Params):
    name: str | None = Param(description="User Name/ID")
    department: str | None = Param(description="User department")
    group: str | None = Param(description="User group")
    limit: float | None = Param(
        description="Maximum number of records to fetch", default=1000
    )


class DepartmentOutput(ActionOutput):
    id: int | None = OutputField(example_values=[81896690])
    name: str | None = OutputField(example_values=["test IT"])


class GroupsOutput(ActionOutput):
    id: int | None = OutputField(
        cef_types=["zscaler group id"],
        column_name="Group ID",
        example_values=[8894813],
    )
    name: str | None = OutputField(
        column_name="Group Name",
        example_values=["test Super Admin"],
    )


class GetUsersOutput(PermissiveActionOutput):
    adminUser: bool | None
    comments: str | None = OutputField(example_values=["test This is test user"])
    deleted: bool | None
    department: DepartmentOutput | None
    disabled: bool | None = OutputField(example_values=[True])
    email: str | None = OutputField(
        cef_types=["email"],
        column_name="User Email",
        example_values=["test first.last@domain.com"],
    )
    groups: list[GroupsOutput] | None
    id: int | None = OutputField(
        cef_types=["zscaler user id"],
        column_name="User ID",
        example_values=[889814],
    )
    isNonEditable: bool | None
    name: str | None = OutputField(
        column_name="User Name",
        example_values=["test First Last"],
    )


class GetUsersSummary(ActionOutput):
    total_users: int = OutputField(example_values=[10])


def get_users(
    params: GetUsersParams, soar: SOARClient, asset: Asset
) -> list[GetUsersOutput]:
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
        raw_users: list[dict[str, Any]] = []
        page = 1
        remaining = limit
        with get_client(asset) as client:
            while remaining > 0:
                query_params: dict[str, str | int] = {
                    "page": page,
                    "page_size": min(remaining, _MAX_PAGE_SIZE),
                }
                for key, value in (
                    ("name", params.name),
                    ("dept", params.department),
                    ("group", params.group),
                ):
                    if value:
                        query_params[key] = value

                _users, response, error = client.zia.user_management.list_users(
                    query_params
                )
                if error is not None:
                    raise RuntimeError(f"Zscaler API error: {error}")
                if response is None:
                    raise RuntimeError("Zscaler API returned no users response")

                page_users = response.get_results()
                if not isinstance(page_users, list):
                    raise RuntimeError("Zscaler API returned an invalid users list")
                if not page_users:
                    break
                for user in page_users:
                    if not isinstance(user, dict):
                        raise RuntimeError(
                            "Zscaler API returned an invalid user record"
                        )
                    raw_users.append(user)
                remaining -= len(page_users)
                page += 1

        rows: list[GetUsersOutput] = []
        for user in raw_users[:limit]:
            if not isinstance(user.get("id"), int) or not isinstance(
                user.get("name"), str
            ):
                raise RuntimeError("Zscaler API returned an invalid user record")

            rows.append(GetUsersOutput(**user))
    except Exception as exc:
        logger.exception("Get users failed")
        message = f"Get users failed: {exc}"
        soar.set_message(message)
        raise ActionFailure(message) from exc

    soar.set_summary(GetUsersSummary(total_users=len(rows)))
    return rows
