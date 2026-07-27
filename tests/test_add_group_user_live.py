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


def test_add_group_user_live_updates_user_and_preserves_contract(
    connector_app: App,
    build_soar_action_input: Callable[..., dict[str, Any]],
    live_asset_config: dict[str, str],
    managed_zia_test_identity: dict[str, int],
) -> None:
    asset = Asset.model_validate(live_asset_config)
    user_id = managed_zia_test_identity["user_id"]
    group_id = managed_zia_test_identity["target_group_id"]

    with get_client(asset) as client:
        user, _response, user_error = client.zia.user_management.get_user(user_id)
        assert user_error is None
        assert user is not None
        target_group, group_response, group_error = (
            client.zia.user_management.get_group(str(group_id))
        )
        assert group_error is None
        assert target_group is not None
        assert group_response is not None
        expected_group = group_response.get_body()
        assert isinstance(expected_group, dict)
        original_user = user.request_format()
        assert group_id not in [group.id for group in user.groups]

    result = None
    idempotent_result = None
    try:
        input_data = build_soar_action_input(
            action="add_group_user",
            parameters={"user_id": user_id, "group_id": group_id},
        )
        connector_app.handle(json.dumps(input_data))
        result = connector_app.actions_manager.get_action_results()[-1]

        with get_client(asset) as client:
            changed, _response, get_error = client.zia.user_management.get_user(user_id)
            assert get_error is None
            assert changed is not None
            assert group_id in [group.id for group in changed.groups]

        connector_app.handle(json.dumps(input_data))
        idempotent_result = connector_app.actions_manager.get_action_results()[-1]
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
    assert result.get_message() == "User successfully added to group"
    assert result.get_data()[0]["id"] == user_id
    assert group_id in [group["id"] for group in result.get_data()[0]["groups"]]
    assert result.get_summary() == {}

    assert idempotent_result is not None
    assert idempotent_result.get_status() is True, idempotent_result.get_message()
    assert idempotent_result.get_message() == "User already in group"
    assert idempotent_result.get_data() == [expected_group]
    assert idempotent_result.get_summary() == {}
