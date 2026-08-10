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


class RemoveGroupUserParams(Params):
    user_id: float = Param(
        description="Zscaler user ID", primary=True, cef_types=["zscaler user id"]
    )
    group_id: float = Param(
        description="Zscaler group ID", primary=True, cef_types=["zscaler group id"]
    )


class DepartmentOutput(ActionOutput):
    id: int = OutputField(example_values=[4459551])
    name: str = OutputField(example_values=["test Service Admin"])


class GroupsOutput(ActionOutput):
    id: int = OutputField(example_values=[4459550])
    name: str = OutputField(example_values=["test Service Admin"])


class RemoveGroupUserOutput(PermissiveActionOutput):
    adminUser: bool | None = OutputField(example_values=[True])
    deleted: bool | None = OutputField(example_values=[False])
    department: DepartmentOutput | None
    email: str | None = OutputField(example_values=["test 134@example.us"])
    groups: list[GroupsOutput] | None
    id: int | None = OutputField(example_values=[9840695])
    name: str | None = OutputField(example_values=["test Elsie"])


def remove_user_from_group(
    params: RemoveGroupUserParams, soar: SOARClient, asset: Asset
) -> RemoveGroupUserOutput:
    for key, value in (("user_id", params.user_id), ("group_id", params.group_id)):
        if not value.is_integer() or value <= 0:
            message = f"{key} must be a positive integer."
            soar.set_message(message)
            raise ActionFailure(message)

    user_id = int(params.user_id)
    group_id = int(params.group_id)

    try:
        with get_client(asset) as client:
            user, response, error = client.zia.user_management.get_user(user_id)
            if error is not None:
                raise RuntimeError(f"Zscaler API error: {error}")
            if user is None or response is None:
                raise RuntimeError("Zscaler API returned no user")

            raw_user = response.get_body()
            if not isinstance(raw_user, dict):
                raise RuntimeError("Zscaler API returned an invalid user")

            if all(existing.id != group_id for existing in user.groups):
                soar.set_message("User already removed from group")
                return RemoveGroupUserOutput(**raw_user)

            if not user.name or len(user.name) > 127:
                raise RuntimeError(
                    "ZIA returned an obfuscated user name. Configure the OneAPI "
                    "client's ZIA API role to make user names visible."
                )

            user_update = user.request_format()
            user_update.pop("password", None)
            updated, updated_response, update_error = (
                client.zia.user_management.update_user(
                    str(user_id),
                    **{
                        **user_update,
                        "groups": [
                            existing.request_format()
                            for existing in user.groups
                            if existing.id != group_id
                        ],
                    },
                )
            )
            if update_error is not None:
                raise RuntimeError(f"Zscaler API error: {update_error}")
            if updated is None or updated_response is None:
                raise RuntimeError("Zscaler API returned no updated user")

            raw_updated = updated_response.get_body()
            if not isinstance(raw_updated, dict):
                raise RuntimeError("Zscaler API returned an invalid updated user")
    except Exception as exc:
        logger.exception("Remove group user failed")
        message = f"Remove group user failed: {exc}"
        soar.set_message(message)
        raise ActionFailure(message) from exc

    soar.set_message("User removed from group")
    return RemoveGroupUserOutput(**raw_updated)
