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


class UnallowIpOutput(PermissiveActionOutput):
    configuredName: str | None = OutputField(example_values=["test Test-Allowlist"])
    customCategory: bool | None = None
    dbCategorizedUrls: list[str] | None = None
    description: str | None = None
    id: str | None = OutputField(example_values=["test CUSTOM_01"])
    val: float | None = OutputField(example_values=[128])
    whitelistUrls: list[str] | None = None


class UnallowIpSummary(PermissiveActionOutput):
    ignored: list[str] = OutputField(example_values=["test 8.8.8.8"])
    updated: list[str] = OutputField(example_values=["test 208.67.222.222"])


def _summary(updated: list[str], ignored: list[str]) -> UnallowIpSummary:
    return UnallowIpSummary(updated=updated, ignored=ignored)


def unallow_ip(
    params: UnallowIpParams, soar: SOARClient, asset: Asset
) -> list[UnallowIpOutput]:
    endpoints = [value.strip() for value in params.ip.split(",") if value.strip()]
    try:
        rows: list[UnallowIpOutput] = []
        with get_client(asset) as client:
            if params.url_category:
                _categories, response, error = (
                    client.zia.url_categories.list_categories()
                )
                if error or response is None:
                    raise RuntimeError(f"Zscaler API error: {error}")
                categories = response.get_results()
                category = next(
                    (
                        item
                        for item in categories
                        if item.get("id") == params.url_category
                        or item.get("configuredName") == params.url_category
                    ),
                    None,
                )
                if category is None:
                    raise RuntimeError("Unable to find category")
                existing = category.get("dbCategorizedUrls", [])
                updated = list(set(existing) & set(endpoints))
                ignored = list(set(endpoints) - set(updated))
                if updated:
                    changed, changed_response, error = (
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
                    if error or changed is None or changed_response is None:
                        raise RuntimeError(f"Zscaler API error: {error}")
                    rows.append(UnallowIpOutput(**changed_response.get_body()))
                empty_message = "Category contains none of these endpoints"
            else:
                settings, _response, error = (
                    client.zia.security_policy_settings.get_whitelist()
                )
                if error or settings is None:
                    raise RuntimeError(f"Zscaler API error: {error}")
                existing = settings.whitelist_urls
                updated = list(set(existing) & set(endpoints))
                ignored = list(set(endpoints) - set(updated))
                if updated:
                    changed, changed_response, error = (
                        client.zia.security_policy_settings.replace_whitelist(
                            list(set(existing) - set(updated))
                        )
                    )
                    if error or changed is None or changed_response is None:
                        raise RuntimeError(f"Zscaler API error: {error}")
                    rows.append(UnallowIpOutput(**changed_response.get_body()))
                empty_message = "Allowlist contains none of these endpoints"

            if not updated:
                soar.set_summary(_summary([], endpoints))
                soar.set_message(empty_message)
                return []
            activation, _response, error = client.zia.activate.activate()
            if error or activation is None:
                raise RuntimeError(
                    "The ZIA change was saved but could not be activated and is not "
                    f"yet enforced. {error}"
                )
    except Exception as exc:
        logger.exception("Unallow IP failed")
        message = f"Unallow IP failed: {exc}"
        soar.set_message(message)
        raise ActionFailure(message) from exc
    soar.set_summary(_summary(updated, ignored))
    return rows
