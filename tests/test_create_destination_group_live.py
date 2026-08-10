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
    build_live_soar_action_input: Callable[..., dict[str, Any]],
    live_asset_config: dict[str, str],
) -> None:
    asset = Asset.model_validate(live_asset_config)
    group_name = f"PAPP-38277 create {uuid4().hex}"
    group_id: int | None = None
    result = None

    try:
        input_data = build_live_soar_action_input(
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
    assert result.get_message() == "Destination group created"
    assert result.get_data()[0]["name"] == group_name
    assert result.get_data()[0]["addresses"] == _TEST_ADDRESSES
    assert result.get_summary() == {}


def test_create_destination_group_live_supports_all_non_ip_types(
    connector_app: App,
    build_live_soar_action_input: Callable[..., dict[str, Any]],
    live_asset_config: dict[str, str],
) -> None:
    asset = Asset.model_validate(live_asset_config)
    with get_client(asset) as client:
        categories, response, error = client.zia.url_categories.list_categories()
        assert error is None
        assert categories
        assert response is not None
        custom_category = next(
            category
            for category in response.get_results()
            if isinstance(category, dict) and category.get("customCategory", False)
        )
        custom_category_id = custom_category["id"]
        assert isinstance(custom_category_id, str)

    cases = [
        (
            "DSTN_FQDN",
            {
                "addresses": "host.papp-38277.example",
            },
        ),
        (
            "DSTN_DOMAIN",
            {
                "addresses": "papp-38277.example",
            },
        ),
        (
            "DSTN_OTHER",
            {
                "countries": "COUNTRY_US",
                "ip_categories": custom_category_id,
            },
        ),
    ]
    created_group_ids: list[int] = []
    attempted_group_names: list[str] = []
    results = []

    try:
        for group_type, type_parameters in cases:
            group_name = f"PAPP-38277 {group_type} {uuid4().hex}"
            attempted_group_names.append(group_name)
            input_data = build_live_soar_action_input(
                action="create_destination_group",
                parameters={
                    "name": group_name,
                    "type": group_type,
                    "description": "Owned by the zscaler_v2 live test suite",
                    **type_parameters,
                },
            )
            connector_app.handle(json.dumps(input_data))
            result = connector_app.actions_manager.get_action_results()[-1]
            results.append(result)

            assert result.get_status() is True, result.get_message()
            row = result.get_data()[0]
            assert row["name"] == group_name
            assert row["type"] == group_type
            assert isinstance(row["id"], int)
            created_group_ids.append(row["id"])

        fqdn_row, domain_row, other_row = [result.get_data()[0] for result in results]
        assert fqdn_row["addresses"] == ["host.papp-38277.example"]
        assert domain_row["addresses"] == ["papp-38277.example"]
        assert other_row["countries"] == ["COUNTRY_US"]
        assert other_row["ipCategories"] == [custom_category_id]
    finally:
        with get_client(asset) as client:
            groups, response, error = (
                client.zia.cloud_firewall.list_ip_destination_groups()
            )
            assert error is None
            assert groups is not None
            assert response is not None
            for group in response.get_results():
                if (
                    isinstance(group, dict)
                    and group.get("name") in attempted_group_names
                    and isinstance(group.get("id"), int)
                    and group["id"] not in created_group_ids
                ):
                    created_group_ids.append(group["id"])

        if created_group_ids:
            with get_client(asset) as client:
                for group_id in created_group_ids:
                    _deleted, _response, error = (
                        client.zia.cloud_firewall.delete_ip_destination_group(group_id)
                    )
                    assert error is None
                activation, _response, error = client.zia.activate.activate()
                assert error is None
                assert activation is not None
