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


class LookupUrlParams(Params):
    url: str = Param(
        description="A list of URLs",
        primary=True,
        cef_types=["url", "domain", "url list"],
        allow_list=True,
    )


class LookupUrlOutput(ActionOutput):
    blocklisted: bool
    url: str = OutputField(
        cef_types=["url", "domain", "url list"], example_values=["test www.test.com"]
    )
    urlClassifications: str = OutputField(
        example_values=["test MISCELLANEOUS_OR_UNKNOWN"]
    )
    urlClassificationsWithSecurityAlert: str


def lookup_url(
    params: LookupUrlParams, soar: SOARClient, asset: Asset
) -> LookupUrlOutput:
    raise NotImplementedError()
