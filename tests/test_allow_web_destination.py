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

from src.actions._validators import validate_web_destination
from src.app import create_zscaler_soar_connector_app


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("HTTPS://example.com/path", "example.com/path"),
        ("192.0.2.10", "192.0.2.10"),
        ("2001:db8::10", "2001:db8::10"),
    ],
)
def test_validate_web_destination_normalizes_supported_values(
    value: str, expected: str
) -> None:
    assert validate_web_destination(value) == expected


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
def test_allow_web_destination_rejects_invalid_input(
    destinations: str,
    message: str,
    connector_app: App,
    build_soar_action_input: Callable[..., dict[str, Any]],
) -> None:
    input_data = build_soar_action_input(
        action="allow_web_destination",
        parameters={"destinations": destinations},
    )

    connector_app.handle(json.dumps(input_data))

    result = connector_app.actions_manager.get_action_results()[-1]
    assert result.get_status() is False
    assert message in result.get_message()


def test_allow_web_destination_validation_runs_before_authentication(
    connector_app: App,
    build_soar_action_input: Callable[..., dict[str, Any]],
) -> None:
    input_data = build_soar_action_input(
        action="allow_web_destination",
        parameters={"destinations": "ftp://example.com"},
    )
    connector_app.handle(json.dumps(input_data))
    result = connector_app.actions_manager.get_action_results()[-1]
    assert result.get_status() is False
    assert "Unsupported web destination scheme" in result.get_message()


def test_allow_web_destination_replaces_old_actions_and_has_expected_contract() -> None:
    app = create_zscaler_soar_connector_app()
    actions = {
        action.identifier: action
        for action in app.actions_manager.get_actions_meta_list()
    }

    assert "allow_ip" not in actions
    assert "allow_url" not in actions

    action = actions["allow_web_destination"]
    serialized = action.model_dump()
    parameter = serialized["parameters"]["destinations"]
    outputs = {
        output["data_path"]: output["data_type"] for output in serialized["output"]
    }

    assert action.action == "allow web destination"
    assert action.type == "contain"
    assert action.read_only is False
    assert serialized["lock"] == {"enabled": True, "concurrency": False}
    assert parameter["required"] is True
    assert parameter["allow_list"] is True
    assert "contains" not in parameter
    assert outputs["action_result.data.*.whitelistUrls.*"] == "string"
    assert outputs["action_result.summary.updated.*"] == "string"
    assert outputs["action_result.summary.ignored.*"] == "string"
