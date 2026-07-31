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

_ORIGINAL_ADDRESS = "192.0.2.203"
_UPDATED_ADDRESSES = ["192.0.2.204", "192.0.2.205"]


def test_edit_destination_group_rejects_fractional_id(
    connector_app: App,
    build_soar_action_input: Callable[..., dict[str, Any]],
) -> None:
    input_data = build_soar_action_input(
        action="edit_destination_group",
        parameters={"ip_group_id": 1.5},
    )
    connector_app.handle(json.dumps(input_data))
    result = connector_app.actions_manager.get_action_results()[-1]

    assert result.get_status() is False
    assert result.get_message() == (
        "Action failure in edit destination group: "
        "Edit destination group failed: ip_group_id must be an integer"
    )


def test_edit_destination_group_live_edits_activates_and_cleans_up(
    connector_app: App,
    build_live_soar_action_input: Callable[..., dict[str, Any]],
    live_asset_config: dict[str, str],
) -> None:
    asset = Asset.model_validate(live_asset_config)
    initial_name = f"PAPP-38277 edit source {uuid4().hex}"
    updated_name = f"PAPP-38277 edit result {uuid4().hex}"
    group_id: int | None = None

    with get_client(asset) as client:
        created, _response, create_error = (
            client.zia.cloud_firewall.add_ip_destination_group(
                name=initial_name,
                type="DSTN_IP",
                addresses=[_ORIGINAL_ADDRESS],
                description="Temporary edit_destination_group fixture",
            )
        )
        assert create_error is None
        assert created is not None
        assert isinstance(created.id, int)
        group_id = created.id

    result = None
    try:
        input_data = build_live_soar_action_input(
            action="edit_destination_group",
            parameters={
                "ip_group_id": group_id,
                "name": updated_name,
                "addresses": ",".join(_UPDATED_ADDRESSES),
                "description": "Updated by the zscaler_v2 live test suite",
                "is_non_editable": False,
            },
        )
        connector_app.handle(json.dumps(input_data))
        result = connector_app.actions_manager.get_action_results()[-1]

        with get_client(asset) as client:
            _changed, response, get_error = (
                client.zia.cloud_firewall.get_ip_destination_group(group_id)
            )
            assert get_error is None
            assert response is not None
            changed = response.get_body()
            assert changed["name"] == updated_name
            assert changed["addresses"] == _UPDATED_ADDRESSES
    finally:
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
    assert result.get_message() == "Destination group edited"
    assert result.get_data()[0]["id"] == group_id
    assert result.get_data()[0]["name"] == updated_name
    assert result.get_data()[0]["addresses"] == _UPDATED_ADDRESSES
    assert result.get_summary() == {}


def test_edit_destination_group_live_preserves_omissions_and_clears_lists(
    connector_app: App,
    build_live_soar_action_input: Callable[..., dict[str, Any]],
    live_asset_config: dict[str, str],
) -> None:
    asset = Asset.model_validate(live_asset_config)
    with get_client(asset) as client:
        categories, response, category_error = (
            client.zia.url_categories.list_categories()
        )
        assert category_error is None
        assert categories
        assert response is not None
        category = next(
            item
            for item in response.get_results()
            if isinstance(item, dict) and item.get("customCategory", False)
        )
        category_id = category["id"]
        assert isinstance(category_id, str)

        original_name = f"PAPP-38277 edit optional {uuid4().hex}"
        original_description = "Description must survive omitted edit parameters"
        created, created_response, create_error = (
            client.zia.cloud_firewall.add_ip_destination_group(
                name=original_name,
                type="DSTN_OTHER",
                description=original_description,
                countries=["COUNTRY_US"],
                ipCategories=[category_id],
            )
        )
        assert create_error is None
        assert created is not None
        assert created_response is not None
        assert isinstance(created.id, int)
        group_id = created.id
        original_group = created_response.get_body()
        assert isinstance(original_group, dict)
        had_is_non_editable = "isNonEditable" in original_group
        original_is_non_editable = original_group.get("isNonEditable")

    updated_name = f"PAPP-38277 edit optional result {uuid4().hex}"
    result = None
    try:
        input_data = build_live_soar_action_input(
            action="edit_destination_group",
            parameters={
                "ip_group_id": group_id,
                "name": updated_name,
                "countries": "",
                "ip_categories": category_id,
            },
        )
        connector_app.handle(json.dumps(input_data))
        result = connector_app.actions_manager.get_action_results()[-1]

        with get_client(asset) as client:
            _group, response, get_error = (
                client.zia.cloud_firewall.get_ip_destination_group(group_id)
            )
            assert get_error is None
            assert response is not None
            changed = response.get_body()
            assert changed["name"] == updated_name
            assert changed["description"] == original_description
            assert changed.get("countries", []) == []
            assert changed["ipCategories"] == [category_id]
            assert ("isNonEditable" in changed) is had_is_non_editable
            assert changed.get("isNonEditable") == original_is_non_editable
    finally:
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
    row = result.get_data()[0]
    assert row["name"] == updated_name
    assert row["description"] == original_description
    assert row.get("countries", []) == []
    assert row["ipCategories"] == [category_id]
    assert ("isNonEditable" in row) is had_is_non_editable
    assert row.get("isNonEditable") == original_is_non_editable
