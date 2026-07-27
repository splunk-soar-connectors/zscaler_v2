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
import ipaddress
import re

from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput, OutputField
from soar_sdk.exceptions import ActionFailure
from soar_sdk.logging import getLogger
from soar_sdk.params import Param, Params

from ..asset import Asset
from ..zscaler_client import get_client

logger = getLogger()


class GetDenylistParams(Params):
    filter: str | None = Param(
        description="Filter results be url or ip",
        primary=True,
        value_list=["url", "ip"],
    )
    query: str | None = Param(
        description="Regular expression to match url or ip against",
        primary=True,
    )


class GetDenylistOutput(ActionOutput):
    url: str = OutputField(column_name="URL")


class GetDenylistSummary(ActionOutput):
    message: str = OutputField(example_values=["Blacklist retrieved"])
    total_denylist_items: int = OutputField(example_values=[10])


def get_denylist(
    params: GetDenylistParams, soar: SOARClient, asset: Asset
) -> list[GetDenylistOutput]:
    try:
        query_pattern = re.compile(params.query) if params.query else None

        with get_client(asset) as client:
            settings, _response, error = (
                client.zia.security_policy_settings.get_blacklist()
            )
            if error is not None:
                raise RuntimeError(f"Zscaler API error: {error}")
            if settings is None:
                raise RuntimeError("Zscaler API returned no denylist settings")

            urls = settings.blacklist_urls
            if not isinstance(urls, list):
                raise RuntimeError("Zscaler API returned an invalid denylist")

        rows: list[GetDenylistOutput] = []
        for blocked in urls:
            blocked_value = str(blocked)
            try:
                ipaddress.ip_address(blocked_value)
                is_ip = True
            except ValueError:
                is_ip = False

            if params.filter == "ip" and not is_ip:
                continue
            if params.filter == "url" and is_ip:
                continue
            if query_pattern and not query_pattern.fullmatch(blocked_value):
                continue
            rows.append(GetDenylistOutput(url=blocked_value))
    except Exception as exc:
        logger.exception("Get denylist failed")
        message = f"Get denylist failed: {exc}"
        soar.set_message(message)
        raise ActionFailure(message) from exc

    message = "Denylist retrieved"
    soar.set_summary(
        GetDenylistSummary(
            message=message,
            total_denylist_items=len(rows),
        )
    )
    soar.set_message(message)
    return rows
