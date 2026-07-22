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


class GetGroupsParams(Params):
    search: str | None = Param(
        description="The search string used to match against a group's name or comments attributes"
    )
    limit: float | None = Param(
        description="Maximum number of records to fetch", default=1000
    )


class GetGroupsOutput(ActionOutput):
    comments: str = OutputField(example_values=["test This is for testing"])
    id: float = OutputField(cef_types=["zscaler group id"], example_values=[8894813])
    isNonEditable: bool = OutputField(example_values=[True])
    name: str = OutputField(example_values=["test Frothly Internet Access"])


def get_groups(
    params: GetGroupsParams, soar: SOARClient, asset: Asset
) -> GetGroupsOutput:
    raise NotImplementedError()
