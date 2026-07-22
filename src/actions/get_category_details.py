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


class GetCategoryDetailsParams(Params):
    category_ids: str | None = Param(
        description="Comma seperated string of category id's to query", primary=True
    )


class ScopesOutput(ActionOutput):
    Type: str = OutputField(example_values=["test ORGANIZATION"])


class GetCategoryDetailsOutput(ActionOutput):
    configuredName: str = OutputField(example_values=["test Test-Caution"])
    customCategory: bool
    keywords: str
    urls: str
    customIpRangesCount: float = OutputField(example_values=[0])
    customUrlsCount: float = OutputField(example_values=[0])
    dbCategorizedUrls: str = OutputField(example_values=["test 6.5.3.2.4"])
    description: str = OutputField(
        example_values=["test OTHER_RESTRICTED_WEBSITE_DESC"]
    )
    editable: bool
    id: str = OutputField(
        cef_types=["zscaler url category"],
        example_values=["test OTHER_RESTRICTED_WEBSITE"],
    )
    ipRangesRetainingParentCategoryCount: float = OutputField(example_values=[0])
    scopes: list[ScopesOutput]
    type: str = OutputField(example_values=["test URL_CATEGORY"])
    urlsRetainingParentCategoryCount: float = OutputField(example_values=[0])
    val: float = OutputField(example_values=[1])


def get_category_details(
    params: GetCategoryDetailsParams, soar: SOARClient, asset: Asset
) -> GetCategoryDetailsOutput:
    raise NotImplementedError()
