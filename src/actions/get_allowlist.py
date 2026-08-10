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
from soar_sdk.action_results import ActionOutput, OutputField
from soar_sdk.exceptions import ActionFailure
from soar_sdk.logging import getLogger
from soar_sdk.params import Params

from ..asset import Asset
from ..zscaler_client import get_client

logger = getLogger()


class GetAllowlistOutput(ActionOutput):
    url: str = OutputField(
        column_name="allowlist url",
        cef_types=["url", "domain", "ip", "ipv6"],
    )


class GetAllowlistSummary(ActionOutput):
    total_allowlist_items: int = OutputField(example_values=[10])


def get_allowlist(
    params: Params, soar: SOARClient, asset: Asset
) -> list[GetAllowlistOutput]:
    try:
        with get_client(asset) as client:
            settings, _response, error = (
                client.zia.security_policy_settings.get_whitelist()
            )
            if error is not None:
                raise RuntimeError(f"Zscaler API error: {error}")

            urls = settings.whitelist_urls
    except Exception as exc:
        logger.exception("Get allowlist failed")
        message = f"Get allowlist failed: {exc}"
        soar.set_message(message)
        raise ActionFailure(message) from exc

    rows = [GetAllowlistOutput(url=str(url)) for url in urls]
    message = "Allowlist retrieved"
    soar.set_summary(GetAllowlistSummary(total_allowlist_items=len(rows)))
    soar.set_message(message)
    return rows
