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
from ._inputs import url_values

logger = getLogger()


class LookupUrlParams(Params):
    url: str = Param(
        description="A list of URLs",
        primary=True,
        cef_types=["url", "domain", "url list"],
        allow_list=True,
    )


class LookupUrlOutput(PermissiveActionOutput):
    url: str | None = OutputField(
        cef_types=["url", "domain", "url list"],
        column_name="URL",
        example_values=["test www.test.com"],
    )
    urlClassifications: list[str] | None = OutputField(
        column_name="Classifications",
        example_values=["test MISCELLANEOUS_OR_UNKNOWN"],
    )
    urlClassificationsWithSecurityAlert: list[str] | None = OutputField(
        column_name="Security Alerts"
    )
    blocklisted: bool | None = OutputField(column_name="Blocklisted")


def lookup_url(
    params: LookupUrlParams, soar: SOARClient, asset: Asset
) -> list[LookupUrlOutput]:
    endpoints = url_values(params.url)

    if not endpoints:
        message = "Please provide a valid list of URLs"
        soar.set_message(message)
        raise ActionFailure(message)
    if any(len(endpoint) > 1024 for endpoint in endpoints):
        message = (
            "Please provide valid comma-separated values in the action parameter. "
            "Max allowed length for each value is 1024."
        )
        soar.set_message(message)
        raise ActionFailure(message)

    try:
        with get_client(asset) as client:
            lookup_results, lookup_error = client.zia.url_categories.lookup(endpoints)
            if lookup_error is not None:
                raise RuntimeError(f"Zscaler API error: {lookup_error}")

            settings, _response, settings_error = (
                client.zia.security_policy_settings.get_blacklist()
            )
            if settings_error is not None:
                raise RuntimeError(f"Zscaler API error: {settings_error}")

        blocklist = set(settings.blacklist_urls)
        rows: list[LookupUrlOutput] = []
        for result in lookup_results:
            if not isinstance(result, dict):
                raise RuntimeError("Zscaler API returned an invalid lookup record")
            row = dict(result)
            row["blocklisted"] = row.get("url") in blocklist
            rows.append(LookupUrlOutput(**row))
    except Exception as exc:
        logger.exception("Lookup URL failed")
        message = f"Lookup URL failed: {exc}"
        soar.set_message(message)
        raise ActionFailure(message) from exc

    soar.set_message("Successfully completed lookup")
    return rows
