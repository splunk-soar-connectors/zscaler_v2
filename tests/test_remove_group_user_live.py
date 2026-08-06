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


def test_remove_group_user_rejects_invalid_ids(
    connector_app: App,
    build_soar_action_input: Callable[..., dict[str, Any]],
) -> None:
    for parameters in (
        {"user_id": 0, "group_id": 1},
        {"user_id": 1, "group_id": 1.5},
    ):
        input_data = build_soar_action_input(
            action="remove_user_from_group",
            parameters=parameters,
        )
        connector_app.handle(json.dumps(input_data))
        result = connector_app.actions_manager.get_action_results()[-1]

        assert result.get_status() is False
        assert "must be a positive integer" in result.get_message()


def test_remove_group_user_live_removes_is_idempotent_and_restores(
    connector_app: App,
    build_live_soar_action_input: Callable[..., dict[str, Any]],
    live_asset_config: dict[str, str],
    managed_zia_test_identity: dict[str, Any],
) -> None:
    user_id = managed_zia_test_identity["user_id"]
    group_id = managed_zia_test_identity["target_group_id"]
    asset = Asset.model_validate(live_asset_config)

    with get_client(asset) as client:
        user, _response, get_error = client.zia.user_management.get_user(user_id)
        assert get_error is None
        assert user is not None
        group, _response, group_error = client.zia.user_management.get_group(
            str(group_id)
        )
        assert group_error is None
        assert group is not None
        original_user = {
            "name": managed_zia_test_identity["user_name"],
            "email": managed_zia_test_identity["user_email"],
            "groups": [{"id": managed_zia_test_identity["base_group_id"]}],
            "department": {"id": managed_zia_test_identity["department_id"]},
            "comments": managed_zia_test_identity["user_comments"],
        }

        prepared, _response, prepare_error = client.zia.user_management.update_user(
            str(user_id),
            **{
                **original_user,
                "groups": [existing.request_format() for existing in user.groups]
                + [group.request_format()],
            },
        )
        assert prepare_error is None
        assert prepared is not None

    first_result = None
    second_result = None
    try:
        input_data = build_live_soar_action_input(
            action="remove_user_from_group",
            parameters={"user_id": user_id, "group_id": group_id},
        )
        connector_app.handle(json.dumps(input_data))
        first_result = connector_app.actions_manager.get_action_results()[-1]
        connector_app.handle(json.dumps(input_data))
        second_result = connector_app.actions_manager.get_action_results()[-1]
    finally:
        with get_client(asset) as client:
            restored, _response, restore_error = client.zia.user_management.update_user(
                str(user_id),
                **original_user,
            )
            assert restore_error is None
            assert restored is not None

    assert first_result is not None
    assert first_result.get_status() is True, first_result.get_message()
    assert first_result.get_message() == "User removed from group"
    assert first_result.get_data()[0]["id"] == user_id
    assert group_id not in [
        group["id"] for group in first_result.get_data()[0]["groups"]
    ]
    assert first_result.get_summary() == {}

    assert second_result is not None
    assert second_result.get_status() is True, second_result.get_message()
    assert second_result.get_message() == "User already removed from group"
    assert second_result.get_data()[0]["id"] == user_id
    assert second_result.get_summary() == {}
