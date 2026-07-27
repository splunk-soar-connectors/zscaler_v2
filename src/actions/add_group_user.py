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
from soar_sdk.action_results import ActionOutput, OutputField, PermissiveActionOutput
from soar_sdk.exceptions import ActionFailure
from soar_sdk.logging import getLogger
from soar_sdk.params import Param, Params

from ..asset import Asset
from ..zscaler_client import get_client

logger = getLogger()


class AddGroupUserParams(Params):
    user_id: float = Param(
        description="Zscaler user ID", primary=True, cef_types=["zscaler user id"]
    )
    group_id: float = Param(
        description="Zscaler group ID", primary=True, cef_types=["zscaler group id"]
    )


class DepartmentOutput(ActionOutput):
    id: float | None = OutputField(example_values=[4459551])
    name: str | None = OutputField(example_values=["test Service Admin"])


class GroupsOutput(ActionOutput):
    id: float | None = OutputField(example_values=[4460341])
    name: str | None = OutputField(example_values=["test Example App"])


class AddGroupUserOutput(PermissiveActionOutput):
    adminUser: bool | None = OutputField(example_values=[True])
    deleted: bool | None = OutputField(example_values=[False])
    department: DepartmentOutput | None
    email: str | None = OutputField(example_values=["test 134@example.us"])
    groups: list[GroupsOutput] | None
    id: float | None = OutputField(example_values=[9840695])
    name: str | None = OutputField(example_values=["test Test user"])


def add_group_user(
    params: AddGroupUserParams, soar: SOARClient, asset: Asset
) -> AddGroupUserOutput:
    for key, value in (("user_id", params.user_id), ("group_id", params.group_id)):
        if not value.is_integer():
            message = f"Please provide a valid integer value in the {key}"
            soar.set_message(message)
            raise ActionFailure(message)
        if value < 0:
            message = f"Please provide a valid non-negative integer value in the {key}"
            soar.set_message(message)
            raise ActionFailure(message)
        if value == 0:
            message = (
                f"Please provide a valid non-zero positive integer value in the {key}"
            )
            soar.set_message(message)
            raise ActionFailure(message)

    user_id = int(params.user_id)
    group_id = int(params.group_id)

    try:
        with get_client(asset) as client:
            user, user_response, user_error = client.zia.user_management.get_user(
                user_id
            )
            if user_error is not None:
                raise RuntimeError(f"Zscaler API error: {user_error}")
            if user is None or user_response is None:
                raise RuntimeError("Zscaler API returned no user")

            group, group_response, group_error = client.zia.user_management.get_group(
                str(group_id)
            )
            if group_error is not None:
                raise RuntimeError(f"Zscaler API error: {group_error}")
            if group is None or group_response is None:
                raise RuntimeError("Zscaler API returned no group")

            raw_group = group_response.get_body()
            if not isinstance(raw_group, dict):
                raise RuntimeError("Zscaler API returned an invalid group")

            if any(existing.id == group_id for existing in user.groups):
                message = "User already in group"
                soar.set_message(message)
                return AddGroupUserOutput(**raw_group)

            updated_user, updated_response, update_error = (
                client.zia.user_management.update_user(
                    str(user_id),
                    **{
                        **user.request_format(),
                        "groups": [
                            existing.request_format() for existing in user.groups
                        ]
                        + [group.request_format()],
                    },
                )
            )
            if update_error is not None:
                raise RuntimeError(f"Zscaler API error: {update_error}")
            if updated_user is None or updated_response is None:
                raise RuntimeError("Zscaler API returned no updated user")

            raw_user = updated_response.get_body()
            if not isinstance(raw_user, dict):
                raise RuntimeError("Zscaler API returned an invalid updated user")
    except Exception as exc:
        logger.exception("Add group user failed")
        message = f"Add group user failed: {exc}"
        soar.set_message(message)
        raise ActionFailure(message) from exc

    soar.set_message("User successfully added to group")
    return AddGroupUserOutput(**raw_user)
