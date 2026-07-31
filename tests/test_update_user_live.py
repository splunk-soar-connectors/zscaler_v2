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

from src.asset import Asset
from src.zscaler_client import get_client

_UPDATED_COMMENT = "Updated by the zscaler_v2 update_user live test"


def test_update_user_rejects_invalid_payloads(
    connector_app: App,
    build_soar_action_input: Callable[..., dict[str, Any]],
) -> None:
    cases = (
        ({"user_id": 0, "user": "{}"}, "positive integer"),
        ({"user_id": 1, "user": "{"}, "valid JSON object"),
        ({"user_id": 1, "user": "{}"}, "non-empty JSON object"),
        (
            {"user_id": 1, "user": '{"password": "unsupported"}'},
            "Password updates are not supported",
        ),
    )

    for parameters, expected_message in cases:
        input_data = build_soar_action_input(
            action="update_user",
            parameters=parameters,
        )
        connector_app.handle(json.dumps(input_data))
        result = connector_app.actions_manager.get_action_results()[-1]

        assert result.get_status() is False
        assert expected_message in result.get_message()


def test_update_user_live_updates_and_restores_managed_profile(
    connector_app: App,
    build_live_soar_action_input: Callable[..., dict[str, Any]],
    live_asset_config: dict[str, str],
    managed_zia_test_identity: dict[str, Any],
) -> None:
    user_id = managed_zia_test_identity["user_id"]
    asset = Asset.model_validate(live_asset_config)

    original_user = {
        "name": managed_zia_test_identity["user_name"],
        "email": managed_zia_test_identity["user_email"],
        "groups": [{"id": managed_zia_test_identity["base_group_id"]}],
        "department": {"id": managed_zia_test_identity["department_id"]},
        "comments": managed_zia_test_identity["user_comments"],
    }
    updated_user = {**original_user, "comments": _UPDATED_COMMENT}

    result = None
    try:
        input_data = build_live_soar_action_input(
            action="update_user",
            parameters={"user_id": user_id, "user": json.dumps(updated_user)},
        )
        connector_app.handle(json.dumps(input_data))
        result = connector_app.actions_manager.get_action_results()[-1]
    finally:
        with get_client(asset) as client:
            restored, _response, restore_error = client.zia.user_management.update_user(
                str(user_id),
                **original_user,
            )
            assert restore_error is None
            assert restored is not None

    assert result is not None
    assert result.get_status() is True, result.get_message()
    assert result.get_message() == "User updated"
    assert result.get_data()[0]["id"] == user_id
    assert result.get_data()[0]["comments"] == _UPDATED_COMMENT
    assert result.get_summary() == {}
