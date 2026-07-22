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


class BlockUrlParams(Params):
    url: str = Param(
        description="A list of URLs",
        primary=True,
        cef_types=["url", "url list", "domain"],
        allow_list=True,
    )
    url_category: str | None = Param(
        description="Add to this category",
        primary=True,
        cef_types=["zscaler url category"],
    )


class BlockUrlOutput(ActionOutput):
    configuredName: str = OutputField(example_values=["test Test-Block"])
    customCategory: bool
    customUrlsCount: float = OutputField(example_values=[0])
    dbCategorizedUrls: str
    description: str
    editable: bool
    id: str = OutputField(example_values=["test CUSTOM_01"])
    type: str = OutputField(example_values=["test URL_CATEGORY"])
    urlsRetainingParentCategoryCount: float = OutputField(example_values=[3])
    val: float = OutputField(example_values=[128])


def block_url(params: BlockUrlParams, soar: SOARClient, asset: Asset) -> BlockUrlOutput:
    raise NotImplementedError()
