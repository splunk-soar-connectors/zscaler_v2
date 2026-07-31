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
from typing import Any, cast

from soar_sdk.action_results import OutputField, PermissiveActionOutput
from soar_sdk.exceptions import ActionFailure
from soar_sdk.logging import getLogger
from soar_sdk.params import Param, Params

from ..asset import Asset
from ..zscaler_client import get_client
from ._inputs import url_values

logger = getLogger()


class UnallowUrlParams(Params):
    url: str = Param(
        description="A list of URLs",
        primary=True,
        cef_types=["url", "domain", "url list"],
        allow_list=True,
    )
    url_category: str | None = Param(
        description="Remove from this category",
        primary=True,
        cef_types=["zscaler url category"],
    )


class UnallowUrlOutput(PermissiveActionOutput):
    configuredName: str | None = OutputField(example_values=["test Test-Allowlist"])
    customCategory: bool | None = None
    dbCategorizedUrls: list[str] | None = None
    description: str | None = None
    id: str | None = OutputField(example_values=["test CUSTOM_01"])
    val: float | None = OutputField(example_values=[128])
    whitelistUrls: list[str] | None = None


class UnallowUrlSummary(PermissiveActionOutput):
    ignored: list[str] = OutputField(example_values=["test www.test.com"])
    updated: list[str] = OutputField(example_values=["test www.test123.com"])


def _summary(updated: list[str], ignored: list[str]) -> UnallowUrlSummary:
    return UnallowUrlSummary(updated=updated, ignored=ignored)


def unallow_url(
    params: UnallowUrlParams, soar: SOARClient, asset: Asset
) -> list[UnallowUrlOutput]:
    endpoints = url_values(params.url)
    if not endpoints:
        message = "Provide at least one non-empty URL"
        soar.set_message(message)
        raise ActionFailure(message)
    if any(len(value) > 1024 for value in endpoints):
        message = (
            "Please provide valid comma-separated values in the action parameter. "
            "Max allowed length for each value is 1024."
        )
        soar.set_message(message)
        raise ActionFailure(message)
    try:
        rows: list[UnallowUrlOutput] = []
        with get_client(asset) as client:
            if params.url_category:
                _, response, error = client.zia.url_categories.list_categories()
                if error or response is None:
                    raise RuntimeError(f"Zscaler API error: {error}")
                category = next(
                    (
                        item
                        for item in response.get_results()
                        if item.get("id") == params.url_category
                        or item.get("configuredName") == params.url_category
                    ),
                    None,
                )
                if category is None:
                    raise RuntimeError("Unable to find category")
                category = cast(dict[str, Any], category)
                existing = category.get("dbCategorizedUrls", [])
                empty_message = "Category contains none of these endpoints"
            else:
                settings, _, error = client.zia.security_policy_settings.get_whitelist()
                if error or settings is None:
                    raise RuntimeError(f"Zscaler API error: {error}")
                existing = settings.whitelist_urls
                empty_message = "Allowlist contains none of these endpoints"
            updated = list(set(existing) & set(endpoints))
            ignored = list(set(endpoints) - set(updated))
            if not updated:
                soar.set_summary(_summary([], endpoints))
                soar.set_message(empty_message)
                return []
            if params.url_category:
                category_data = cast(dict[str, Any], category)
                changed, response, error = (
                    client.zia.url_categories.delete_urls_from_category(
                        str(category_data["id"]),
                        configuredName=category_data.get("configuredName"),
                        keywordsRetainingParentCategory=category_data.get(
                            "keywordsRetainingParentCategory", []
                        ),
                        urls=[],
                        dbCategorizedUrls=updated,
                    )
                )
            else:
                changed, response, error = (
                    client.zia.security_policy_settings.replace_whitelist(
                        list(set(existing) - set(updated))
                    )
                )
            if error or changed is None or response is None:
                raise RuntimeError(f"Zscaler API error: {error}")
            rows.append(UnallowUrlOutput(**response.get_body()))
            activation, _, error = client.zia.activate.activate()
            if error or activation is None:
                raise RuntimeError(
                    "The ZIA change was saved but could not be activated and is not "
                    f"yet enforced. {error}"
                )
    except Exception as exc:
        logger.exception("Unallow URL failed")
        message = f"Unallow URL failed: {exc}"
        soar.set_message(message)
        raise ActionFailure(message) from exc
    soar.set_summary(_summary(updated, ignored))
    return rows
