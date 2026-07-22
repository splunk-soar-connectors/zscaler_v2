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
from soar_sdk.params import Param, Params

from ..asset import Asset


class UpdateUserParams(Params):
    user_id: float = Param(
        description="ZScaler User Id", primary=True, cef_types=["zscaler user id"]
    )
    user: str | None = Param(
        description="JSON object containing the user details (see https://help.zscaler.com/zia/user-management#/users/{userId}-put)",
        primary=True,
    )


class DepartmentOutput(ActionOutput):
    id: float = OutputField(example_values=[81896690])
    name: str = OutputField(example_values=["test IT"])


class GroupsOutput(ActionOutput):
    id: float = OutputField(cef_types=["zscaler group id"], example_values=[8894813])
    name: str = OutputField(example_values=["test Super Admin"])


class UpdateUserOutput(ActionOutput):
    adminUser: bool
    comments: str = OutputField(example_values=["test This is test user"])
    deleted: bool
    department: DepartmentOutput
    email: str = OutputField(
        cef_types=["email"], example_values=["test first.last@domain.com"]
    )
    groups: list[GroupsOutput]
    id: float = OutputField(cef_types=["zscaler user id"], example_values=[889814])
    name: str = OutputField(example_values=["test First Last"])


def update_user(
    params: UpdateUserParams, soar: SOARClient, asset: Asset
) -> UpdateUserOutput:
    raise NotImplementedError()
