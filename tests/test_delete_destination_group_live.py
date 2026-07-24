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


def test_delete_destination_group_live_deletes_multiple_and_preserves_legacy_rows(
    connector_app: App,
    build_soar_action_input: Callable[..., dict[str, Any]],
    live_asset_config: dict[str, str],
) -> None:
    asset = Asset.model_validate(live_asset_config)
    group_ids: list[int] = []

    with get_client(asset) as client:
        for index in range(2):
            created, _response, create_error = (
                client.zia.cloud_firewall.add_ip_destination_group(
                    name=f"PAPP-38277 delete {index} {uuid4().hex}",
                    type="DSTN_IP",
                    addresses=[f"192.0.2.{206 + index}"],
                    description="Temporary delete_destination_group fixture",
                )
            )
            assert create_error is None
            assert created is not None
            assert isinstance(created.id, int)
            group_ids.append(created.id)

    result = None
    try:
        input_data = build_soar_action_input(
            action="delete_destination_group",
            parameters={"ip_group_ids": ",".join(map(str, group_ids))},
        )
        connector_app.handle(json.dumps(input_data))
        result = connector_app.actions_manager.get_action_results()[-1]

        with get_client(asset) as client:
            for group_id in group_ids:
                _group, _response, get_error = (
                    client.zia.cloud_firewall.get_ip_destination_group(group_id)
                )
                assert get_error is not None
    finally:
        with get_client(asset) as client:
            for group_id in group_ids:
                _group, _response, get_error = (
                    client.zia.cloud_firewall.get_ip_destination_group(group_id)
                )
                if get_error is None:
                    _deleted, _response, delete_error = (
                        client.zia.cloud_firewall.delete_ip_destination_group(group_id)
                    )
                    assert delete_error is None

    assert result is not None
    assert result.get_status() is True, result.get_message()
    assert result.get_data() == [
        {"ip_group_id": str(group_id)} for group_id in group_ids
    ]
    assert result.get_summary() == {"message": "Destination groups deleted"}
