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


class AllowWebDestinationParams(Params):
    destinations: str = Param(
        description=(
            "A comma-separated list of URLs, domains, IPv4 addresses, or IPv6 addresses"
        ),
        primary=True,
        allow_list=True,
    )


class AllowWebDestinationOutput(PermissiveActionOutput):
    whitelistUrls: list[str] = OutputField(
        example_values=["test example.com", "test 192.0.2.10"]
    )


class AllowWebDestinationSummary(PermissiveActionOutput):
    ignored: list[str] = OutputField(example_values=["test example.com"])
    updated: list[str] = OutputField(example_values=["test 192.0.2.10"])


def _summary(updated: list[str], ignored: list[str]) -> AllowWebDestinationSummary:
    return AllowWebDestinationSummary(updated=updated, ignored=ignored)


def allow_web_destination(
    params: AllowWebDestinationParams, soar: SOARClient, asset: Asset
) -> list[AllowWebDestinationOutput]:
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
            settings, _response, error = (
                client.zia.security_policy_settings.get_whitelist()
            )
            if error is not None:
                raise RuntimeError(f"Zscaler API error: {error}")
            if settings is None:
                raise RuntimeError("Zscaler API returned no allowlist")

            existing = settings.whitelist_urls
            existing_set = set(existing)
            updated = [item for item in destinations if item not in existing_set]
            ignored = [item for item in destinations if item in existing_set]
            if not updated:
                soar.set_summary(_summary(updated=[], ignored=ignored))
                soar.set_message("Allowlist contains all of these destinations")
                return []

            changed, changed_response, change_error = (
                client.zia.security_policy_settings.replace_whitelist(
                    [*existing, *updated]
                )
            )
            if change_error is not None:
                raise RuntimeError(f"Zscaler API error: {change_error}")
            if changed is None or changed_response is None:
                raise RuntimeError("Zscaler API returned no updated allowlist")

            raw_result = changed_response.get_body()
            if not isinstance(raw_result, dict):
                raise RuntimeError("Zscaler API returned an invalid updated allowlist")
            row = AllowWebDestinationOutput(**raw_result)

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
        logger.exception("Allow web destination failed")
        message = f"Allow web destination failed: {exc}"
        soar.set_message(message)
        raise ActionFailure(message) from exc

    soar.set_summary(_summary(updated=updated, ignored=ignored))
    return [row]
