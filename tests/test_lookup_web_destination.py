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
from src.app import create_zscaler_soar_connector_app


def test_lookup_web_destination_validates_before_authentication(
    connector_app: App, build_soar_action_input: Callable[..., dict[str, Any]]
) -> None:
    connector_app.handle(
        json.dumps(
            build_soar_action_input(
                action="lookup_web_destination",
                parameters={"destinations": "ftp://example.com"},
            )
        )
    )
    result = connector_app.actions_manager.get_action_results()[-1]
    assert result.get_status() is False
    assert "Unsupported web destination scheme" in result.get_message()


def test_lookup_web_destination_replaces_old_actions_and_renders_destination() -> None:
    actions = {
        action.identifier: action
        for action in create_zscaler_soar_connector_app().actions_manager.get_actions_meta_list()
    }
    assert "lookup_ip" not in actions
    assert "lookup_url" not in actions
    action = actions["lookup_web_destination"]
    serialized = action.model_dump()
    assert action.read_only is True
    assert serialized["render"] == {"type": "table"}
    outputs = {item["data_path"]: item for item in serialized["output"]}
    assert outputs["action_result.data.*.destination"]["column_name"] == "Destination"
