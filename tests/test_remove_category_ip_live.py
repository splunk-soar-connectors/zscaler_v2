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

_TEST_IP = "203.0.113.199"
_TEST_PARENT_IP = "203.0.113.200"


def test_remove_category_ip_live_removes_activates_and_preserves_legacy_lists(
    connector_app: App,
    build_soar_action_input: Callable[..., dict[str, Any]],
    live_asset_config: dict[str, str],
) -> None:
    asset = Asset.model_validate(live_asset_config)
    with get_client(asset) as client:
        categories, response, list_error = client.zia.url_categories.list_categories()
        assert list_error is None
        assert categories
        assert response is not None
        category = next(
            item
            for item in response.get_results()
            if isinstance(item, dict) and item.get("customCategory", False)
        )
        category_id = category["id"]
        configured_name = category["configuredName"]
        assert isinstance(category_id, str)
        assert isinstance(configured_name, str)

        prepared, _response, prepare_error = (
            client.zia.url_categories.add_urls_to_category(
                category_id,
                configuredName=configured_name,
                urls=[_TEST_IP],
                dbCategorizedUrls=[_TEST_PARENT_IP],
            )
        )
        assert prepare_error is None
        assert prepared is not None

    result = None
    try:
        input_data = build_soar_action_input(
            action="remove_category_ip",
            parameters={
                "category_id": category_id,
                "ips": _TEST_IP,
                "retaining-parent-category-ip": _TEST_PARENT_IP,
            },
        )
        connector_app.handle(json.dumps(input_data))
        result = connector_app.actions_manager.get_action_results()[-1]

        with get_client(asset) as client:
            _changed, changed_response, get_error = (
                client.zia.url_categories.get_category(category_id)
            )
            assert get_error is None
            assert changed_response is not None
            changed = changed_response.get_body()
            assert _TEST_IP not in changed["urls"]
            assert _TEST_PARENT_IP not in changed["dbCategorizedUrls"]
    finally:
        with get_client(asset) as client:
            _current, current_response, current_error = (
                client.zia.url_categories.get_category(category_id)
            )
            assert current_error is None
            assert current_response is not None
            current = current_response.get_body()
            if _TEST_IP in current.get("urls", []) or _TEST_PARENT_IP in current.get(
                "dbCategorizedUrls", []
            ):
                cleaned, _response, cleanup_error = (
                    client.zia.url_categories.delete_urls_from_category(
                        category_id,
                        configuredName=configured_name,
                        urls=[_TEST_IP],
                        dbCategorizedUrls=[_TEST_PARENT_IP],
                    )
                )
                assert cleanup_error is None
                assert cleaned is not None
                activation, _response, activation_error = client.zia.activate.activate()
                assert activation_error is None
                assert activation is not None

    assert result is not None
    assert result.get_status() is True, result.get_message()
    assert result.get_data()[0]["id"] == category_id
    assert _TEST_IP not in result.get_data()[0]["urls"]
    assert _TEST_PARENT_IP not in result.get_data()[0]["dbCategorizedUrls"]
    assert result.get_summary() == {"message": "Category ips removed"}
