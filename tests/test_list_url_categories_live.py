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
import json
from collections.abc import Callable
from typing import Any

from soar_sdk.app import App


def test_list_url_categories_live_returns_full_oneapi_response(
    connector_app: App,
    build_live_soar_action_input: Callable[..., dict[str, Any]],
) -> None:
    input_data = build_live_soar_action_input(
        action="list_url_categories",
        parameters={"get_ids_and_names_only": False},
    )

    connector_app.handle(json.dumps(input_data))

    result = connector_app.actions_manager.get_action_results()[-1]
    assert result.get_status() is True, result.get_message()

    rows = result.get_data()
    assert rows
    assert all(isinstance(row["id"], str) for row in rows)
    assert any(
        isinstance(row.get("dbCategorizedUrls"), list)
        for row in rows
        if "dbCategorizedUrls" in row
    )
    assert result.get_summary() == {"total_url_categories": len(rows)}


def test_list_url_categories_live_supports_ids_and_names_only(
    connector_app: App,
    build_live_soar_action_input: Callable[..., dict[str, Any]],
) -> None:
    input_data = build_live_soar_action_input(
        action="list_url_categories",
        parameters={"get_ids_and_names_only": True},
    )

    connector_app.handle(json.dumps(input_data))

    result = connector_app.actions_manager.get_action_results()[-1]
    assert result.get_status() is True, result.get_message()

    rows = result.get_data()
    assert rows
    assert all(set(row) <= {"id", "configuredName"} for row in rows)
    assert all(isinstance(row["id"], str) for row in rows)
    assert result.get_summary() == {"total_url_categories": len(rows)}
