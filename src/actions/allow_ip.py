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
from ._inputs import validated_ip_values

logger = getLogger()


class AllowIpParams(Params):
    ip: str = Param(
        description="A list of IPs",
        primary=True,
        cef_types=["ip", "ipv6"],
        allow_list=True,
    )
    url_category: str | None = Param(
        description="Add to this category",
        primary=True,
        cef_types=["zscaler url category"],
    )


class AllowIpOutput(PermissiveActionOutput):
    configuredName: str | None = OutputField(example_values=["test Test-Allowlist"])
    customCategory: bool | None = None
    dbCategorizedUrls: list[str] | None = None
    description: str | None = None
    id: str | None = OutputField(example_values=["test CUSTOM_01"])
    val: float | None = OutputField(example_values=[128])
    whitelistUrls: list[str] | None = None


class AllowIpSummary(PermissiveActionOutput):
    ignored: list[str] = OutputField(example_values=["test 8.8.8.8"])
    updated: list[str] = OutputField(example_values=["test 208.67.222.222"])


def _summary(updated: list[str], ignored: list[str]) -> AllowIpSummary:
    return AllowIpSummary(updated=updated, ignored=ignored)


def allow_ip(
    params: AllowIpParams, soar: SOARClient, asset: Asset
) -> list[AllowIpOutput]:
    endpoints = validated_ip_values(params.ip, soar)
    if not endpoints:
        message = "Provide at least one non-empty IP address"
        soar.set_message(message)
        raise ActionFailure(message)
    try:
        rows: list[AllowIpOutput] = []
        with get_client(asset) as client:
            if params.url_category:
                _categories, response, error = (
                    client.zia.url_categories.list_categories()
                )
                if error is not None:
                    raise RuntimeError(f"Zscaler API error: {error}")
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
                updated = list(set(endpoints) - set(existing))
                ignored = list(set(endpoints) - set(updated))
                if not updated:
                    message = "Category contains all of these endpoints"
                    soar.set_summary(_summary(updated=[], ignored=endpoints))
                    soar.set_message(message)
                    return []
                category_result, category_response, category_error = (
                    client.zia.url_categories.add_urls_to_category(
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
                rows.append(AllowIpOutput(**raw_result))
            else:
                settings, _response, error = (
                    client.zia.security_policy_settings.get_whitelist()
                )
                if error is not None:
                    raise RuntimeError(f"Zscaler API error: {error}")
                existing = settings.whitelist_urls
                updated = list(set(endpoints) - set(existing))
                ignored = list(set(endpoints) - set(updated))
                if not updated:
                    message = "Allowlist contains all of these endpoints"
                    soar.set_summary(_summary(updated=[], ignored=endpoints))
                    soar.set_message(message)
                    return []

                changed, changed_response, change_error = (
                    client.zia.security_policy_settings.replace_whitelist(
                        list(set(existing + updated))
                    )
                )
                if change_error is not None:
                    raise RuntimeError(f"Zscaler API error: {change_error}")
                if changed is None or changed_response is None:
                    raise RuntimeError("Zscaler API returned no updated allowlist")
                raw_result = changed_response.get_body()
                if not isinstance(raw_result, dict):
                    raise RuntimeError(
                        "Zscaler API returned an invalid updated allowlist"
                    )
                rows.append(AllowIpOutput(**raw_result))

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
        logger.exception("Allow IP failed")
        message = f"Allow IP failed: {exc}"
        soar.set_message(message)
        raise ActionFailure(message) from exc

    soar.set_summary(_summary(updated=updated, ignored=ignored))
    return rows
