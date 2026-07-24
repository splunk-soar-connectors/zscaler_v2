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

_TEST_URL = "papp-38277-category.example"
_TEST_PARENT_URL = "papp-38277-parent-category.example"


def test_add_category_url_live_updates_activates_and_preserves_contract(
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
        raw_categories = response.get_results()
        category = next(
            item
            for item in raw_categories
            if isinstance(item, dict) and item.get("customCategory", False)
        )
        category_id = category["id"]
        assert isinstance(category_id, str)
        configured_name = category["configuredName"]
        assert isinstance(configured_name, str)
        assert _TEST_URL not in category.get("urls", [])
        assert _TEST_PARENT_URL not in category.get("dbCategorizedUrls", [])

    result = None
    try:
        input_data = build_soar_action_input(
            action="add_category_url",
            parameters={
                "category_id": category_id,
                "urls": _TEST_URL,
                "retaining-parent-category-url": _TEST_PARENT_URL,
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
            assert _TEST_URL in changed["urls"]
            assert _TEST_PARENT_URL in changed["dbCategorizedUrls"]
    finally:
        with get_client(asset) as client:
            cleaned, _response, cleanup_error = (
                client.zia.url_categories.delete_urls_from_category(
                    category_id,
                    configuredName=configured_name,
                    urls=[_TEST_URL],
                    dbCategorizedUrls=[_TEST_PARENT_URL],
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
    assert _TEST_URL in result.get_data()[0]["urls"]
    assert _TEST_PARENT_URL in result.get_data()[0]["dbCategorizedUrls"]
    assert result.get_summary() == {"message": "Category urls updated"}
