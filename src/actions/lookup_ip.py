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


class LookupIpParams(Params):
    ip: str = Param(
        description="A list of IPs",
        primary=True,
        cef_types=["ip", "ipv6"],
        allow_list=True,
    )


class LookupIpOutput(ActionOutput):
    blocklisted: bool
    url: str = OutputField(
        cef_types=["ip", "ipv6"], example_values=["test 208.67.222.222", "test 8.8.8.8"]
    )
    urlClassifications: str = OutputField(example_values=["test WEB_SEARCH"])
    urlClassificationsWithSecurityAlert: str


def lookup_ip(params: LookupIpParams, soar: SOARClient, asset: Asset) -> LookupIpOutput:
    raise NotImplementedError()
