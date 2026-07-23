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


def test_list_destination_group_live_supports_full_and_lite_id_queries(
    connector_app: App,
    build_soar_action_input: Callable[..., dict[str, Any]],
) -> None:
    list_input = build_soar_action_input(
        action="list_destination_group",
        parameters={"limit": 2, "lite": False},
    )
    connector_app.handle(json.dumps(list_input))
    list_result = connector_app.actions_manager.get_action_results()[-1]
    assert list_result.get_status() is True, list_result.get_message()

    full_rows = list_result.get_data()
    assert 0 < len(full_rows) <= 2
    assert all(isinstance(row["id"], int) for row in full_rows)
    assert all(isinstance(row["name"], str) for row in full_rows)
    assert all(isinstance(row["type"], str) for row in full_rows)
    assert list_result.get_summary() == {"message": "Destination groups retrieved"}

    group_ids = [str(row["id"]) for row in full_rows]
    lite_input = build_soar_action_input(
        action="list_destination_group",
        parameters={
            "ip_group_ids": ", ".join(group_ids),
            "category_type": ",".join({row["type"] for row in full_rows}),
            "lite": True,
        },
    )
    connector_app.handle(json.dumps(lite_input))
    lite_result = connector_app.actions_manager.get_action_results()[-1]

    assert lite_result.get_status() is True, lite_result.get_message()
    assert lite_result.get_message() == "Destination groups retrieved"
    lite_rows = lite_result.get_data()
    assert [str(row["id"]) for row in lite_rows] == group_ids
    assert all(set(row) == {"id", "name", "type"} for row in lite_rows)
