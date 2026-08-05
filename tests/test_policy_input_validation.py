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

POLICY_ACTIONS = ()


@pytest.mark.parametrize(
    ("action", "parameter_name", "expected_kind"),
    POLICY_ACTIONS,
    ids=[action for action, *_rest in POLICY_ACTIONS],
)
def test_policy_actions_reject_empty_comma_separated_input(
    action: str,
    parameter_name: str,
    expected_kind: str,
    connector_app: App,
    build_soar_action_input: Callable[..., dict[str, Any]],
) -> None:
    input_data = build_soar_action_input(
        action=action,
        parameters={parameter_name: " , , "},
    )
    connector_app.handle(json.dumps(input_data))
    result = connector_app.actions_manager.get_action_results()[-1]

    assert result.get_status() is False
    assert f"Provide at least one non-empty {expected_kind}" in result.get_message()


@pytest.mark.parametrize(
    ("action", "parameters"),
    [
        (
            "remove_category_ip",
            {"category_id": "CUSTOM_01", "ips": "not-an-ip"},
        ),
    ],
)
def test_ip_actions_reject_non_ip_values_before_api_call(
    action: str,
    parameters: dict[str, str],
    connector_app: App,
    build_soar_action_input: Callable[..., dict[str, Any]],
) -> None:
    input_data = build_soar_action_input(action=action, parameters=parameters)

    connector_app.handle(json.dumps(input_data))

    result = connector_app.actions_manager.get_action_results()[-1]
    assert result.get_status() is False
    assert "Invalid IP address value(s): not-an-ip" in result.get_message()
