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


class RemoveGroupUserParams(Params):
    user_id: float = Param(
        description="ZScaler User Id", primary=True, cef_types=["zscaler user id"]
    )
    group_id: float = Param(
        description="ZScaler Group Id", primary=True, cef_types=["zscaler group id"]
    )


class DepartmentOutput(ActionOutput):
    id: float = OutputField(example_values=[4459551])
    name: str = OutputField(example_values=["test Service Admin"])


class GroupsOutput(ActionOutput):
    id: float = OutputField(example_values=[4459550])
    name: str = OutputField(example_values=["test Service Admin"])


class RemoveGroupUserOutput(ActionOutput):
    adminUser: bool = OutputField(example_values=[True])
    deleted: bool = OutputField(example_values=[False])
    department: DepartmentOutput
    email: str = OutputField(example_values=["test 134@example.us"])
    groups: list[GroupsOutput]
    id: float = OutputField(example_values=[9840695])
    name: str = OutputField(example_values=["test Elsie"])


def remove_group_user(
    params: RemoveGroupUserParams, soar: SOARClient, asset: Asset
) -> RemoveGroupUserOutput:
    raise NotImplementedError()
