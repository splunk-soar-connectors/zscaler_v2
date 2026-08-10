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

import pytest
from soar_sdk.app import App
from src.app import create_zscaler_soar_connector_app


@pytest.mark.parametrize(
    "parameters",
    [
        {"category_id": "CUSTOM_01"},
        {"category_id": "CUSTOM_01", "destinations": " , , "},
        {
            "category_id": "CUSTOM_01",
            "retaining_parent_category_destinations": " , , ",
        },
    ],
)
def test_remove_category_destination_requires_a_destination(
    connector_app: App,
    build_soar_action_input: Callable[..., dict[str, Any]],
    parameters: dict[str, str],
) -> None:
    connector_app.handle(
        json.dumps(
            build_soar_action_input(
                action="remove_category_destination",
                parameters=parameters,
            )
        )
    )
    result = connector_app.actions_manager.get_action_results()[-1]
    assert result.get_status() is False
    assert "Provide at least one value" in result.get_message()


def test_remove_category_destination_replaces_old_actions() -> None:
    actions = {
        action.identifier: action
        for action in create_zscaler_soar_connector_app().actions_manager.get_actions_meta_list()
    }
    assert "remove_category_ip" not in actions
    assert "remove_category_url" not in actions
    action = actions["remove_category_destination"]
    assert action.read_only is False
    assert action.model_dump()["lock"] == {"enabled": True, "concurrency": False}
