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
from soar_sdk.action_results import OutputField, PermissiveActionOutput
from soar_sdk.exceptions import ActionFailure
from soar_sdk.logging import getLogger
from soar_sdk.params import Param, Params

from ..asset import Asset
from ..zscaler_client import get_client

logger = getLogger()


class UnblockUrlParams(Params):
    url: str = Param(
        description="A list of URLs",
        primary=True,
        cef_types=["url", "url list", "domain"],
        allow_list=True,
    )
    url_category: str | None = Param(
        description="Remove from this category",
        primary=True,
        cef_types=["zscaler url category"],
    )


class UnblockUrlOutput(PermissiveActionOutput):
    configuredName: str | None = OutputField(example_values=["test Test-Block"])
    customCategory: bool | None = None
    customUrlsCount: float | None = OutputField(example_values=[0])
    dbCategorizedUrls: list[str] | None = None
    description: str | None = None
    editable: bool | None = None
    id: str | None = OutputField(example_values=["test CUSTOM_01"])
    type: str | None = OutputField(example_values=["test URL_CATEGORY"])
    urlsRetainingParentCategoryCount: float | None = OutputField(example_values=[1])
    val: float | None = OutputField(example_values=[128])


class UnblockUrlSummary(PermissiveActionOutput):
    ignored: list[str] = OutputField(example_values=["test www.test.com"])
    updated: list[str] = OutputField(example_values=["test www.test123.com"])


def _summary(updated: list[str], ignored: list[str]) -> UnblockUrlSummary:
    return UnblockUrlSummary(updated=updated, ignored=ignored)


def unblock_url(
    params: UnblockUrlParams, soar: SOARClient, asset: Asset
) -> list[UnblockUrlOutput]:
    endpoints = [
        endpoint.strip() for endpoint in params.url.split(",") if endpoint.strip()
    ]
    if not endpoints:
        message = "Provide at least one non-empty URL"
        soar.set_message(message)
        raise ActionFailure(message)
    for index, endpoint in enumerate(endpoints):
        if endpoint.startswith("http://"):
            endpoints[index] = endpoint[len("http://") :]
        elif endpoint.startswith("https://"):
            endpoints[index] = endpoint[len("https://") :]

    if any(len(endpoint) > 1024 for endpoint in endpoints):
        message = (
            "Please provide valid comma-separated values in the action parameter. "
            "Max allowed length for each value is 1024."
        )
        soar.set_message(message)
        raise ActionFailure(message)

    try:
        rows: list[UnblockUrlOutput] = []
        with get_client(asset) as client:
            if params.url_category:
                categories, response, error = (
                    client.zia.url_categories.list_categories()
                )
                if error is not None:
                    raise RuntimeError(f"Zscaler API error: {error}")
                if not isinstance(categories, list) or response is None:
                    raise RuntimeError("Zscaler API returned an invalid category list")
                raw_categories = response.get_results()
                if not isinstance(raw_categories, list):
                    raise RuntimeError("Zscaler API returned an invalid category list")
                category = next(
                    (
                        item
                        for item in raw_categories
                        if isinstance(item, dict)
                        and (
                            item.get("configuredName") == params.url_category
                            or item.get("id") == params.url_category
                        )
                    ),
                    None,
                )
                if category is None:
                    raise RuntimeError("Unable to find category")

                existing = category.get("dbCategorizedUrls", [])
                if not isinstance(existing, list):
                    raise RuntimeError("Zscaler API returned an invalid category")
                updated = list(set(existing) - (set(existing) - set(endpoints)))
                ignored = list(set(endpoints) - set(updated))
                if not updated:
                    message = "Category contains none of these endpoints"
                    soar.set_summary(_summary(updated=[], ignored=endpoints))
                    soar.set_message(message)
                    return []

                category_result, category_response, category_error = (
                    client.zia.url_categories.delete_urls_from_category(
                        str(category["id"]),
                        configuredName=category.get("configuredName"),
                        keywordsRetainingParentCategory=category.get(
                            "keywordsRetainingParentCategory", []
                        ),
                        urls=[],
                        dbCategorizedUrls=updated,
                    )
                )
                if category_error is not None:
                    raise RuntimeError(f"Zscaler API error: {category_error}")
                if category_result is None or category_response is None:
                    raise RuntimeError(
                        "Zscaler API returned no updated category response"
                    )
                raw_result = category_response.get_body()
                if not isinstance(raw_result, dict):
                    raise RuntimeError(
                        "Zscaler API returned an invalid updated category"
                    )
                rows.append(UnblockUrlOutput(**raw_result))
            else:
                settings, _response, error = (
                    client.zia.security_policy_settings.get_blacklist()
                )
                if error is not None:
                    raise RuntimeError(f"Zscaler API error: {error}")
                if settings is None or not isinstance(settings.blacklist_urls, list):
                    raise RuntimeError("Zscaler API returned an invalid blocklist")
                existing = settings.blacklist_urls
                updated = list(set(existing) - (set(existing) - set(endpoints)))
                ignored = list(set(endpoints) - set(updated))
                if not updated:
                    message = "Blocklist contains none of these endpoints"
                    soar.set_summary(_summary(updated=[], ignored=endpoints))
                    soar.set_message(message)
                    return []

                changed, _changed_response, change_error = (
                    client.zia.security_policy_settings.delete_urls_from_blacklist(
                        updated
                    )
                )
                if change_error is not None:
                    raise RuntimeError(f"Zscaler API error: {change_error}")
                if changed is None:
                    raise RuntimeError("Zscaler API returned no updated blocklist")

            activation, _activation_response, activation_error = (
                client.zia.activate.activate()
            )
            if activation_error is not None or activation is None:
                detail = activation_error or "Zscaler API returned no activation data"
                raise RuntimeError(
                    "The ZIA change was saved but could not be activated and is not "
                    f"yet enforced. {detail}"
                )
    except Exception as exc:
        logger.exception("Unblock URL failed")
        message = f"Unblock URL failed: {exc}"
        soar.set_message(message)
        raise ActionFailure(message) from exc

    soar.set_summary(_summary(updated=updated, ignored=ignored))
    return rows
