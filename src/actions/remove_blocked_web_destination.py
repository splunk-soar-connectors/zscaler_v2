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


class RemoveBlockedWebDestinationParams(Params):
    destinations: str = Param(
        description="A comma-separated list of URLs, domains, IPv4 addresses, or IPv6 addresses",
        primary=True,
        cef_types=["url", "domain", "ip", "ipv6", "url list"],
        allow_list=True,
    )


class RemoveBlockedWebDestinationOutput(PermissiveActionOutput):
    pass


class RemoveBlockedWebDestinationSummary(PermissiveActionOutput):
    ignored: list[str] = OutputField(example_values=["test example.com"])
    updated: list[str] = OutputField(example_values=["test 192.0.2.10"])


def _summary(
    updated: list[str], ignored: list[str]
) -> RemoveBlockedWebDestinationSummary:
    return RemoveBlockedWebDestinationSummary(updated=updated, ignored=ignored)


def remove_blocked_web_destination(
    params: RemoveBlockedWebDestinationParams, soar: SOARClient, asset: Asset
) -> list[RemoveBlockedWebDestinationOutput]:
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
                client.zia.security_policy_settings.get_blacklist()
            )
            if error is not None:
                raise RuntimeError(f"Zscaler API error: {error}")
            if settings is None:
                raise RuntimeError("Zscaler API returned no blocklist")
            existing_set = set(settings.blacklist_urls)
            updated = [item for item in destinations if item in existing_set]
            ignored = [item for item in destinations if item not in existing_set]
            if not updated:
                soar.set_summary(_summary(updated=[], ignored=ignored))
                soar.set_message("Blocklist contains none of these destinations")
                return []
            changed, _response, change_error = (
                client.zia.security_policy_settings.delete_urls_from_blacklist(updated)
            )
            if change_error is not None:
                raise RuntimeError(f"Zscaler API error: {change_error}")
            if changed is None:
                raise RuntimeError("Zscaler API returned no updated blocklist")
            activation, _response, activation_error = client.zia.activate.activate()
            if activation_error is not None or activation is None:
                detail = activation_error or "Zscaler API returned no activation data"
                raise RuntimeError(
                    "The ZIA change was saved but could not be activated and is not "
                    f"yet enforced. {detail}"
                )
    except Exception as exc:
        logger.exception("Remove blocked web destination failed")
        message = f"Remove blocked web destination failed: {exc}"
        soar.set_message(message)
        raise ActionFailure(message) from exc

    soar.set_summary(_summary(updated=updated, ignored=ignored))
    return []
