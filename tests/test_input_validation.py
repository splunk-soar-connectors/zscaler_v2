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


def _run_action(
    connector_app: App,
    build_soar_action_input: Callable[..., dict[str, Any]],
    *,
    action: str,
    parameters: dict[str, Any],
) -> Any:
    connector_app.handle(
        json.dumps(
            build_soar_action_input(action=action, parameters=parameters),
        )
    )
    return connector_app.actions_manager.get_action_results()[-1]


@pytest.mark.parametrize(
    "action",
    [
        "get_admin_users",
        "get_groups",
        "get_users",
        "list_destination_group",
    ],
)
@pytest.mark.parametrize("limit", [0, -1, 1.5])
def test_read_actions_reject_non_positive_or_fractional_limits(
    connector_app: App,
    build_soar_action_input: Callable[..., dict[str, Any]],
    action: str,
    limit: float,
) -> None:
    result = _run_action(
        connector_app,
        build_soar_action_input,
        action=action,
        parameters={"limit": limit},
    )

    assert result.get_status() is False
    assert "Limit must be a positive integer" in result.get_message()


@pytest.mark.parametrize(
    ("action", "parameter_name", "value", "expected_message"),
    [
        (
            "lookup_web_destination",
            "destinations",
            " , ",
            "Provide at least one non-empty web destination",
        ),
        (
            "lookup_web_destination",
            "destinations",
            "x" * 1025,
            "Max allowed length for each web destination is 1024",
        ),
    ],
)
def test_lookup_web_destination_rejects_invalid_values_before_api_call(
    connector_app: App,
    build_soar_action_input: Callable[..., dict[str, Any]],
    action: str,
    parameter_name: str,
    value: str,
    expected_message: str,
) -> None:
    result = _run_action(
        connector_app,
        build_soar_action_input,
        action=action,
        parameters={parameter_name: value},
    )

    assert result.get_status() is False
    assert expected_message in result.get_message()


@pytest.mark.parametrize(
    "parameters",
    [
        {"user_id": 0, "group_id": 1},
        {"user_id": -1, "group_id": 1},
        {"user_id": 1.5, "group_id": 1},
        {"user_id": 1, "group_id": 0},
        {"user_id": 1, "group_id": -1},
        {"user_id": 1, "group_id": 1.5},
    ],
)
def test_add_group_user_rejects_invalid_ids_before_api_call(
    connector_app: App,
    build_soar_action_input: Callable[..., dict[str, Any]],
    parameters: dict[str, float],
) -> None:
    result = _run_action(
        connector_app,
        build_soar_action_input,
        action="add_group_user",
        parameters=parameters,
    )

    assert result.get_status() is False
    assert "valid" in result.get_message()
    assert "integer" in result.get_message()
