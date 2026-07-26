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


class LookupIpParams(Params):
    ip: str = Param(
        description="A list of IPs",
        primary=True,
        cef_types=["ip", "ipv6"],
        allow_list=True,
    )


class LookupIpOutput(PermissiveActionOutput):
    blocklisted: bool | None = OutputField(column_name="Blocklisted")
    url: str | None = OutputField(
        cef_types=["ip", "ipv6"],
        column_name="Ip/Url",
        example_values=["test 208.67.222.222", "test 8.8.8.8"],
    )
    urlClassifications: list[str] | None = OutputField(
        column_name="Classifications",
        example_values=["test WEB_SEARCH"],
    )
    urlClassificationsWithSecurityAlert: list[str] | None = OutputField(
        column_name="Security Alerts"
    )


def lookup_ip(
    params: LookupIpParams, soar: SOARClient, asset: Asset
) -> list[LookupIpOutput]:
    endpoints = [
        endpoint.strip() for endpoint in params.ip.split(",") if endpoint.strip()
    ]
    if not endpoints:
        message = "Please provide valid list of URL(s)"
        soar.set_message(message)
        raise ActionFailure(message)

    try:
        with get_client(asset) as client:
            lookup_results, lookup_error = client.zia.url_categories.lookup(endpoints)
            if lookup_error is not None:
                raise RuntimeError(f"Zscaler API error: {lookup_error}")
            if not isinstance(lookup_results, list):
                raise RuntimeError("Zscaler API returned an invalid lookup response")

            settings, _response, settings_error = (
                client.zia.security_policy_settings.get_blacklist()
            )
            if settings_error is not None:
                raise RuntimeError(f"Zscaler API error: {settings_error}")
            if settings is None or not isinstance(settings.blacklist_urls, list):
                raise RuntimeError("Zscaler API returned an invalid blocklist")

        blocklist = set(settings.blacklist_urls)
        rows: list[LookupIpOutput] = []
        for result in lookup_results:
            if not isinstance(result, dict):
                raise RuntimeError("Zscaler API returned an invalid lookup record")
            row = dict(result)
            row["blocklisted"] = row.get("url") in blocklist
            rows.append(LookupIpOutput(**row))
    except Exception as exc:
        logger.exception("Lookup IP failed")
        message = f"Lookup IP failed: {exc}"
        soar.set_message(message)
        raise ActionFailure(message) from exc

    soar.set_message("Successfully completed lookup")
    return rows
