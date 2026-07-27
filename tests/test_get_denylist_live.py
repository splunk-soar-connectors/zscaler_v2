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
import json
from collections.abc import Callable
from typing import Any

from soar_sdk.app import App


def _run_get_denylist(
    connector_app: App,
    build_soar_action_input: Callable[..., dict[str, Any]],
    parameters: dict[str, Any] | None = None,
) -> Any:
    input_data = build_soar_action_input(
        action="get_denylist",
        parameters=parameters,
    )
    connector_app.handle(json.dumps(input_data))
    return connector_app.actions_manager.get_action_results()[-1]


def test_get_denylist_live(
    connector_app: App,
    build_soar_action_input: Callable[..., dict[str, Any]],
) -> None:
    result = _run_get_denylist(connector_app, build_soar_action_input)

    assert result.get_status() is True, result.get_message()
    assert result.get_message() == "Denylist retrieved"

    rows = result.get_data()
    assert all(isinstance(row.get("url"), str) for row in rows)
    assert result.get_summary() == {
        "total_denylist_items": len(rows),
    }


def test_get_denylist_live_filters_ip_entries(
    connector_app: App,
    build_soar_action_input: Callable[..., dict[str, Any]],
) -> None:
    result = _run_get_denylist(
        connector_app,
        build_soar_action_input,
        {"filter": "ip", "query": ".*"},
    )

    assert result.get_status() is True, result.get_message()
    for row in result.get_data():
        ipaddress.ip_address(row["url"])


def test_get_denylist_live_filters_url_entries(
    connector_app: App,
    build_soar_action_input: Callable[..., dict[str, Any]],
) -> None:
    result = _run_get_denylist(
        connector_app,
        build_soar_action_input,
        {"filter": "url", "query": ".*"},
    )

    assert result.get_status() is True, result.get_message()
    for row in result.get_data():
        try:
            ipaddress.ip_address(row["url"])
        except ValueError:
            continue
        raise AssertionError(f"IP address returned by URL filter: {row['url']}")
