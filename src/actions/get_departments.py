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
from soar_sdk.action_results import ActionOutput
from soar_sdk.params import Param, Params

from ..asset import Asset


class GetDepartmentsParams(Params):
    name: str | None = Param(description="Filter by department name", primary=True)
    page: float | None = Param(description="Specifies the page offset", primary=True)
    pageSize: float | None = Param(
        description="Specifies the page size", primary=True, default=100
    )


class GetDepartmentsOutput(ActionOutput):
    id: float
    name: str
    isNonEditable: bool


def get_departments(
    params: GetDepartmentsParams, soar: SOARClient, asset: Asset
) -> GetDepartmentsOutput:
    raise NotImplementedError()
