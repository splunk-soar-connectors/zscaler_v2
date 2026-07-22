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


class UnallowIpParams(Params):
    ip: str = Param(
        description="A list of IPs",
        primary=True,
        cef_types=["ip", "ipv6"],
        allow_list=True,
    )
    url_category: str | None = Param(
        description="Remove from this category",
        primary=True,
        cef_types=["zscaler url category"],
    )


class UnallowIpOutput(ActionOutput):
    configuredName: str = OutputField(example_values=["test Test-Allowlist"])
    customCategory: bool
    dbCategorizedUrls: str
    description: str
    id: str = OutputField(example_values=["test CUSTOM_01"])
    val: float = OutputField(example_values=[128])


def unallow_ip(
    params: UnallowIpParams, soar: SOARClient, asset: Asset
) -> UnallowIpOutput:
    raise NotImplementedError()
