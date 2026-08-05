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
from ._validators import validate_web_destination

logger = getLogger()


class LookupWebDestinationParams(Params):
    destinations: str = Param(
        description="A comma-separated list of URLs, domains, IPv4 addresses, or IPv6 addresses",
        primary=True,
        cef_types=["url", "domain", "ip", "ipv6", "url list"],
        allow_list=True,
    )


class LookupWebDestinationOutput(PermissiveActionOutput):
    destination: str = OutputField(
        cef_types=["url", "domain", "ip", "ipv6"],
        column_name="Destination",
        example_values=["test example.com", "test 8.8.8.8"],
    )
    urlClassifications: list[str] = OutputField(
        column_name="Classifications", example_values=["test WEB_SEARCH"]
    )
    urlClassificationsWithSecurityAlert: list[str] = OutputField(
        column_name="Security Alerts"
    )
    blocklisted: bool = OutputField(column_name="Blocklisted")


def lookup_web_destination(
    params: LookupWebDestinationParams, soar: SOARClient, asset: Asset
) -> list[LookupWebDestinationOutput]:
    values = [item.strip() for item in params.destinations.split(",") if item.strip()]
    try:
        if not values:
            raise ValueError("Provide at least one non-empty web destination")
        destinations: list[str] = []
        for value in values:
            destination = validate_web_destination(value)
            if destination not in destinations:
                destinations.append(destination)
    except ValueError as exc:
        message = str(exc)
        soar.set_message(message)
        raise ActionFailure(message) from exc

    try:
        with get_client(asset) as client:
            lookup_results, lookup_error = client.zia.url_categories.lookup(
                destinations
            )
            if lookup_error is not None:
                raise RuntimeError(f"Zscaler API error: {lookup_error}")
            settings, _response, settings_error = (
                client.zia.security_policy_settings.get_blacklist()
            )
            if settings_error is not None:
                raise RuntimeError(f"Zscaler API error: {settings_error}")
            if settings is None:
                raise RuntimeError("Zscaler API returned no blocklist")

        blocklist = set(settings.blacklist_urls)
        rows: list[LookupWebDestinationOutput] = []
        for result in lookup_results:
            if not isinstance(result, dict):
                raise RuntimeError("Zscaler API returned an invalid lookup record")
            destination = result.get("url")
            if not isinstance(destination, str):
                raise RuntimeError(
                    "Zscaler API returned a lookup record without a destination"
                )
            rows.append(
                LookupWebDestinationOutput(
                    destination=destination,
                    urlClassifications=result.get("urlClassifications", []),
                    urlClassificationsWithSecurityAlert=result.get(
                        "urlClassificationsWithSecurityAlert", []
                    ),
                    blocklisted=destination in blocklist,
                )
            )
    except Exception as exc:
        logger.exception("Lookup web destination failed")
        message = f"Lookup web destination failed: {exc}"
        soar.set_message(message)
        raise ActionFailure(message) from exc

    soar.set_message("Successfully completed web destination lookup")
    return rows
