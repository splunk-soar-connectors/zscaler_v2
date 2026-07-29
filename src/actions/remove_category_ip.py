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
from soar_sdk.action_results import PermissiveActionOutput
from soar_sdk.exceptions import ActionFailure
from soar_sdk.logging import getLogger
from soar_sdk.params import Param, Params

from ..asset import Asset
from ..zscaler_client import get_client

logger = getLogger()


class RemoveCategoryIpParams(Params):
    category_id: str = Param(
        description="The ID of the category to remove the specified IP addresses from",
        primary=True,
    )
    ips: str | None = Param(
        description="A comma-separated list of IP addresses to remove from the specified category",
        primary=True,
        default=None,
    )
    retaining_parent_category_ip: str | None = Param(
        description="A comma-separated list of IP addresses to remove from the category's retaining-parent-category list",
        primary=True,
        default=None,
    )


class ScopesOutput(PermissiveActionOutput):
    Type: str | None = None


class RemoveCategoryIpOutput(PermissiveActionOutput):
    id: str | None = None
    val: float | None = None
    type: str | None = None
    urls: list[str] | None = None
    scopes: list[ScopesOutput] | None = None
    editable: bool | None = None
    keywords: list[str] | None = None
    description: str | None = None
    configuredName: str | None = None
    customCategory: bool | None = None
    customUrlsCount: float | None = None
    dbCategorizedUrls: list[str] | None = None
    customIpRangesCount: float | None = None
    keywordsRetainingParentCategory: list[str] | None = None
    urlsRetainingParentCategoryCount: float | None = None
    ipRangesRetainingParentCategoryCount: float | None = None


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
            result = RemoveCategoryIpOutput(**raw_updated)

            activation, _response, activation_error = client.zia.activate.activate()
            if activation_error is not None or activation is None:
                detail = activation_error or "Zscaler API returned no activation data"
                raise RuntimeError(
                    "The category change was saved but could not be activated and is "
                    f"not yet enforced. {detail}"
                )
    except Exception as exc:
        logger.exception("Remove category IP failed")
        message = f"Remove category IP failed: {exc}"
        soar.set_message(message)
        raise ActionFailure(message) from exc

    soar.set_message("Category IPs removed")
    return result
