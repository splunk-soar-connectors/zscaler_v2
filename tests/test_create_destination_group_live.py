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
from uuid import uuid4

from soar_sdk.app import App

from src.asset import Asset
from src.zscaler_client import get_client

_TEST_ADDRESSES = ["192.0.2.201", "192.0.2.202"]


def test_create_destination_group_live_creates_activates_and_cleans_up(
    connector_app: App,
    build_soar_action_input: Callable[..., dict[str, Any]],
    live_asset_config: dict[str, str],
) -> None:
    asset = Asset.model_validate(live_asset_config)
    group_name = f"PAPP-38277 create {uuid4().hex}"
    group_id: int | None = None
    result = None

    try:
        input_data = build_soar_action_input(
            action="create_destination_group",
            parameters={
                "name": group_name,
                "type": "DSTN_IP",
                "addresses": ",".join(_TEST_ADDRESSES),
                "description": "Owned by the zscaler_v2 live test suite",
            },
        )
        connector_app.handle(json.dumps(input_data))
        result = connector_app.actions_manager.get_action_results()[-1]
        if result.get_status() is True:
            group_id = result.get_data()[0]["id"]

        assert isinstance(group_id, int)
        with get_client(asset) as client:
            _group, response, get_error = (
                client.zia.cloud_firewall.get_ip_destination_group(group_id)
            )
            assert get_error is None
            assert response is not None
            created = response.get_body()
            assert created["name"] == group_name
            assert created["addresses"] == _TEST_ADDRESSES
    finally:
        if group_id is None:
            with get_client(asset) as client:
                groups, _response, list_error = (
                    client.zia.cloud_firewall.list_ip_destination_groups(
                        query_params={"search": group_name}
                    )
                )
                assert list_error is None
                matching_group = next(
                    (
                        group
                        for group in groups or []
                        if group.as_dict().get("name") == group_name
                    ),
                    None,
                )
                if matching_group is not None:
                    discovered_id = matching_group.as_dict().get("id")
                    assert isinstance(discovered_id, int)
                    group_id = discovered_id

        if group_id is not None:
            with get_client(asset) as client:
                _deleted, _response, delete_error = (
                    client.zia.cloud_firewall.delete_ip_destination_group(group_id)
                )
                assert delete_error is None
                activation, _response, activation_error = client.zia.activate.activate()
                assert activation_error is None
                assert activation is not None

    assert result is not None
    assert result.get_status() is True, result.get_message()
    assert result.get_data()[0]["name"] == group_name
    assert result.get_data()[0]["addresses"] == _TEST_ADDRESSES
    assert result.get_summary() == {"message": "Destination Group Created"}
