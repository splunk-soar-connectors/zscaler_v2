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


def test_get_groups_live_preserves_legacy_rows(
    connector_app: App,
    build_soar_action_input: Callable[..., dict[str, Any]],
) -> None:
    input_data = build_soar_action_input(
        action="get_groups",
        parameters={"limit": 3},
    )

    connector_app.handle(json.dumps(input_data))

    result = connector_app.actions_manager.get_action_results()[-1]
    assert result.get_status() is True, result.get_message()

    rows = result.get_data()
    assert 0 < len(rows) <= 3
    assert all(
        {"id", "name"} <= set(row) <= {"comments", "id", "isNonEditable", "name"}
        for row in rows
    )
    assert all(isinstance(row["id"], int) for row in rows)
    assert all(isinstance(row["name"], str) for row in rows)
    assert all(
        "comments" not in row or isinstance(row["comments"], str) for row in rows
    )
    assert all(
        "isNonEditable" not in row or isinstance(row["isNonEditable"], bool)
        for row in rows
    )
    assert result.get_summary() == {"total_groups": len(rows)}


def test_get_groups_live_filters_by_search(
    connector_app: App,
    build_soar_action_input: Callable[..., dict[str, Any]],
) -> None:
    initial_input = build_soar_action_input(
        action="get_groups",
        parameters={"limit": 1},
    )
    connector_app.handle(json.dumps(initial_input))
    initial_result = connector_app.actions_manager.get_action_results()[-1]
    assert initial_result.get_status() is True, initial_result.get_message()
    group_name = initial_result.get_data()[0]["name"]

    filtered_input = build_soar_action_input(
        action="get_groups",
        parameters={"search": group_name, "limit": 10},
    )
    connector_app.handle(json.dumps(filtered_input))
    filtered_result = connector_app.actions_manager.get_action_results()[-1]

    assert filtered_result.get_status() is True, filtered_result.get_message()
    assert group_name in {group["name"] for group in filtered_result.get_data()}
