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


def test_get_users_live_preserves_raw_contract(
    connector_app: App,
    build_soar_action_input: Callable[..., dict[str, Any]],
) -> None:
    input_data = build_soar_action_input(
        action="get_users",
        parameters={"limit": 2},
    )

    connector_app.handle(json.dumps(input_data))

    result = connector_app.actions_manager.get_action_results()[-1]
    assert result.get_status() is True, result.get_message()

    rows = result.get_data()
    assert 0 < len(rows) <= 2
    assert all(isinstance(row["id"], int) for row in rows)
    assert all(isinstance(row["name"], str) for row in rows)
    assert all(isinstance(row["email"], str) for row in rows)
    assert all(isinstance(row["groups"], list) for row in rows)
    assert all(
        "department" not in row or isinstance(row["department"], dict) for row in rows
    )
    assert all("pilotUser" in row for row in rows)
    assert result.get_summary() == {"total_users": len(rows)}


def test_get_users_live_filters_by_department(
    connector_app: App,
    build_soar_action_input: Callable[..., dict[str, Any]],
) -> None:
    initial_input = build_soar_action_input(
        action="get_users",
        parameters={"limit": 10},
    )
    connector_app.handle(json.dumps(initial_input))
    initial_result = connector_app.actions_manager.get_action_results()[-1]
    assert initial_result.get_status() is True, initial_result.get_message()
    department_name = next(
        user["department"]["name"]
        for user in initial_result.get_data()
        if user.get("department")
    )

    filtered_input = build_soar_action_input(
        action="get_users",
        parameters={"dept": department_name, "limit": 10},
    )
    connector_app.handle(json.dumps(filtered_input))
    filtered_result = connector_app.actions_manager.get_action_results()[-1]

    assert filtered_result.get_status() is True, filtered_result.get_message()
    assert filtered_result.get_data()
    assert all(
        user["department"]["name"].startswith(department_name)
        for user in filtered_result.get_data()
    )
