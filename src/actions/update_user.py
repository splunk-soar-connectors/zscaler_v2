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
import json

from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput, OutputField, PermissiveActionOutput
from soar_sdk.exceptions import ActionFailure
from soar_sdk.logging import getLogger
from soar_sdk.params import Param, Params

from ..asset import Asset
from ..zscaler_client import get_client

logger = getLogger()


class UpdateUserParams(Params):
    user_id: float = Param(
        description="Zscaler user ID", primary=True, cef_types=["zscaler user id"]
    )
    user: str = Param(
        description="JSON object containing the user details (see https://help.zscaler.com/zia/user-management#/users/{userId}-put)",
        primary=True,
    )


class DepartmentOutput(ActionOutput):
    id: int = OutputField(example_values=[81896690])
    name: str = OutputField(example_values=["test IT"])


class GroupsOutput(ActionOutput):
    id: int = OutputField(cef_types=["zscaler group id"], example_values=[8894813])
    name: str = OutputField(example_values=["test Super Admin"])


class UpdateUserOutput(PermissiveActionOutput):
    adminUser: bool | None
    comments: str | None = OutputField(example_values=["test This is test user"])
    deleted: bool | None
    department: DepartmentOutput | None
    email: str | None = OutputField(
        cef_types=["email"], example_values=["test first.last@domain.com"]
    )
    groups: list[GroupsOutput] | None
    id: int | None = OutputField(cef_types=["zscaler user id"], example_values=[889814])
    name: str | None = OutputField(example_values=["test First Last"])


def update_user(
    params: UpdateUserParams, soar: SOARClient, asset: Asset
) -> UpdateUserOutput:
    if not params.user_id.is_integer() or params.user_id <= 0:
        message = "user_id must be a positive integer."
        soar.set_message(message)
        raise ActionFailure(message)

    try:
        user_data = json.loads(params.user)
    except (TypeError, json.JSONDecodeError) as exc:
        message = f"User must be a valid JSON object: {exc}"
        soar.set_message(message)
        raise ActionFailure(message) from exc
    if not isinstance(user_data, dict) or not user_data:
        message = "User must be a non-empty JSON object."
        soar.set_message(message)
        raise ActionFailure(message)
    if "password" in user_data:
        message = "Password updates are not supported by this action."
        soar.set_message(message)
        raise ActionFailure(message)

    try:
        with get_client(asset) as client:
            updated, response, error = client.zia.user_management.update_user(
                str(int(params.user_id)),
                **user_data,
            )
            if error is not None:
                raise RuntimeError(f"Zscaler API error: {error}")
            if updated is None or response is None:
                raise RuntimeError("Zscaler API returned no updated user")

            raw_updated = response.get_body()
            if not isinstance(raw_updated, dict):
                raise RuntimeError("Zscaler API returned an invalid updated user")
    except Exception as exc:
        logger.exception("Update user failed")
        message = f"Update user failed: {exc}"
        soar.set_message(message)
        raise ActionFailure(message) from exc

    soar.set_message("User updated")
    return UpdateUserOutput(**raw_updated)
