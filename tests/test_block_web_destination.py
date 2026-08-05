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
    ("destinations", "message"),
    [
        (" , , ", "Provide at least one non-empty web destination"),
        ("https://", "Web destination cannot be empty"),
        ("ftp://example.com", "Unsupported web destination scheme"),
        ("example .com", "Web destination cannot contain whitespace"),
        ("999.999.999.999", "Invalid IP address value"),
        ("x" * 1025, "Max allowed length for each web destination is 1024"),
    ],
)
def test_block_web_destination_rejects_invalid_input(
    destinations: str,
    message: str,
    connector_app: App,
    build_soar_action_input: Callable[..., dict[str, Any]],
) -> None:
    connector_app.handle(
        json.dumps(
            build_soar_action_input(
                action="block_web_destination",
                parameters={"destinations": destinations},
            )
        )
    )
    result = connector_app.actions_manager.get_action_results()[-1]
    assert result.get_status() is False
    assert message in result.get_message()


def test_block_web_destination_replaces_old_actions() -> None:
    actions = {
        action.identifier: action
        for action in create_zscaler_soar_connector_app().actions_manager.get_actions_meta_list()
    }
    assert "block_ip" not in actions
    assert "block_url" not in actions

    action = actions["block_web_destination"]
    serialized = action.model_dump()
    parameter = serialized["parameters"]["destinations"]
    assert action.action == "block web destination"
    assert action.type == "contain"
    assert action.read_only is False
    assert serialized["lock"] == {"enabled": True, "concurrency": False}
    assert parameter["required"] is True
    assert parameter["allow_list"] is True
    assert "contains" not in parameter
