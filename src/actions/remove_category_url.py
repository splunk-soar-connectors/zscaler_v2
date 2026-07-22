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


class RemoveCategoryUrlParams(Params):
    category_id: str = Param(
        description="The ID of the category to add the specified URLs to", primary=True
    )
    urls: str | None = Param(
        description="A comma-separated list of URLs to remove from the specified category",
        primary=True,
    )
    retaining_parent_category_url: str | None = Param(
        description="A comma-separated list of URLs to remove from the retaining parent category section inside the specified category",
        primary=True,
        alias="retaining-parent-category-url",
    )


class ScopesOutput(ActionOutput):
    Type: str


class RemoveCategoryUrlOutput(ActionOutput):
    id: str
    val: float
    type: str
    urls: str
    scopes: list[ScopesOutput]
    editable: bool
    keywords: str
    description: str
    configuredName: str
    customCategory: bool
    customUrlsCount: float
    dbCategorizedUrls: str
    customIpRangesCount: float
    keywordsRetainingParentCategory: str
    urlsRetainingParentCategoryCount: float
    ipRangesRetainingParentCategoryCount: float


def remove_category_url(
    params: RemoveCategoryUrlParams, soar: SOARClient, asset: Asset
) -> RemoveCategoryUrlOutput:
    raise NotImplementedError()
