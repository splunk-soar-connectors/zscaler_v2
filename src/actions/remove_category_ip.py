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
from soar_sdk.exceptions import ActionFailure
from soar_sdk.logging import getLogger
from soar_sdk.params import Param, Params

from ..asset import Asset
from ..zscaler_client import get_client

logger = getLogger()


class RemoveCategoryIpParams(Params):
    category_id: str = Param(
        description="The ID of the category to add the specified URLs to", primary=True
    )
    ips: str | None = Param(
        description="A comma-separated list of IP addresses to add to the specified category",
        primary=True,
        default=None,
    )
    retaining_parent_category_ip: str | None = Param(
        description="A comma-separated list of IPs to add to the retaining parent category section inside the specified category",
        primary=True,
        default=None,
    )


class ScopesOutput(ActionOutput):
    Type: str


class RemoveCategoryIpOutput(ActionOutput):
    id: str
    val: float
    type: str
    urls: list[str]
    scopes: list[ScopesOutput]
    editable: bool
    keywords: list[str]
    description: str
    configuredName: str
    customCategory: bool
    customUrlsCount: float
    dbCategorizedUrls: list[str]
    customIpRangesCount: float
    keywordsRetainingParentCategory: list[str]
    urlsRetainingParentCategoryCount: float
    ipRangesRetainingParentCategoryCount: float


class RemoveCategoryIpSummary(ActionOutput):
    message: str = OutputField(example_values=["Category ips removed"])


def remove_category_ip(
    params: RemoveCategoryIpParams, soar: SOARClient, asset: Asset
) -> RemoveCategoryIpOutput:
    ips = [item.strip() for item in (params.ips or "").split(",") if item.strip()]
    parent_ips = [
        item.strip()
        for item in (params.retaining_parent_category_ip or "").split(",")
        if item.strip()
    ]
    if not ips and not parent_ips:
        message = "Provide at least one IP in ips or retaining_parent_category_ip"
        soar.set_message(message)
        raise ActionFailure(message)

    try:
        with get_client(asset) as client:
            category, category_response, category_error = (
                client.zia.url_categories.get_category(params.category_id)
            )
            if category_error is not None:
                raise RuntimeError(f"Zscaler API error: {category_error}")
            if category is None or category_response is None:
                raise RuntimeError("Zscaler API returned no category")

            raw_category = category_response.get_body()
            if not isinstance(raw_category, dict):
                raise RuntimeError("Zscaler API returned an invalid category")
            configured_name = raw_category.get("configuredName")
            if not isinstance(configured_name, str):
                raise RuntimeError("Zscaler API returned a category without a name")

            updated, updated_response, update_error = (
                client.zia.url_categories.delete_urls_from_category(
                    params.category_id,
                    configuredName=configured_name,
                    urls=ips,
                    dbCategorizedUrls=parent_ips,
                )
            )
            if update_error is not None:
                raise RuntimeError(f"Zscaler API error: {update_error}")
            if updated is None or updated_response is None:
                raise RuntimeError("Zscaler API returned no updated category")

            raw_updated = updated_response.get_body()
            if not isinstance(raw_updated, dict):
                raise RuntimeError("Zscaler API returned an invalid updated category")

            activation, _response, activation_error = client.zia.activate.activate()
            if activation_error is not None:
                raise RuntimeError(f"Zscaler API error: {activation_error}")
            if activation is None:
                raise RuntimeError("Zscaler API returned no activation response")
    except Exception as exc:
        logger.exception("Remove category IP failed")
        message = f"Remove category IP failed: {exc}"
        soar.set_message(message)
        raise ActionFailure(message) from exc

    soar.set_summary(RemoveCategoryIpSummary(message="Category ips removed"))
    return RemoveCategoryIpOutput.model_construct(**raw_updated)
