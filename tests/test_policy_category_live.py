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

from src.asset import Asset
from src.zscaler_client import get_client


def _custom_category(asset: Asset) -> tuple[str, str, list[str]]:
    with get_client(asset) as client:
        categories, response, error = client.zia.url_categories.list_categories()
        assert error is None
        assert categories
        assert response is not None
        category = next(
            item
            for item in response.get_results()
            if isinstance(item, dict) and item.get("customCategory", False)
        )

    category_id = category["id"]
    configured_name = category["configuredName"]
    db_categorized_urls = category.get("dbCategorizedUrls", [])
    assert isinstance(category_id, str)
    assert isinstance(configured_name, str)
    assert isinstance(db_categorized_urls, list)
    return category_id, configured_name, db_categorized_urls


def _category_urls(asset: Asset, category_id: str) -> list[str]:
    with get_client(asset) as client:
        _category, response, error = client.zia.url_categories.get_category(category_id)
        assert error is None
        assert response is not None
        body = response.get_body()
        assert isinstance(body, dict)
        urls = body.get("dbCategorizedUrls", [])
        assert isinstance(urls, list)
        return urls


@pytest.mark.parametrize(
    ("add_action", "remove_action", "parameter_name", "endpoint"),
    [
        ("block_ip", "unblock_ip", "ip", "198.51.100.202"),
        ("block_url", "unblock_url", "url", "papp-38277-block.example"),
    ],
)
def test_block_category_live_lifecycle_is_idempotent(
    connector_app: App,
    build_live_soar_action_input: Callable[..., dict[str, Any]],
    live_asset_config: dict[str, str],
    add_action: str,
    remove_action: str,
    parameter_name: str,
    endpoint: str,
) -> None:
    asset = Asset.model_validate(live_asset_config)
    category_id, configured_name, existing = _custom_category(asset)
    assert endpoint not in existing

    results = []
    try:
        for action in (add_action, add_action, remove_action, remove_action):
            connector_app.handle(
                json.dumps(
                    build_live_soar_action_input(
                        action=action,
                        parameters={
                            parameter_name: endpoint,
                            "url_category": configured_name,
                        },
                    )
                )
            )
            results.append(connector_app.actions_manager.get_action_results()[-1])

        assert endpoint not in _category_urls(asset, category_id)
    finally:
        if endpoint in _category_urls(asset, category_id):
            with get_client(asset) as client:
                _changed, _response, error = (
                    client.zia.url_categories.delete_urls_from_category(
                        category_id,
                        configuredName=configured_name,
                        urls=[],
                        dbCategorizedUrls=[endpoint],
                    )
                )
                assert error is None
                activation, _response, error = client.zia.activate.activate()
                assert error is None
                assert activation is not None

    added, add_idempotent, removed, remove_idempotent = results
    assert added.get_status() is True, added.get_message()
    assert endpoint in added.get_data()[0]["dbCategorizedUrls"]
    assert added.get_summary() == {"updated": [endpoint], "ignored": []}
    assert add_idempotent.get_status() is True, add_idempotent.get_message()
    assert add_idempotent.get_message() == "Category contains all of these endpoints"
    assert add_idempotent.get_summary() == {"updated": [], "ignored": [endpoint]}
    assert removed.get_status() is True, removed.get_message()
    assert endpoint not in removed.get_data()[0]["dbCategorizedUrls"]
    assert removed.get_summary() == {"updated": [endpoint], "ignored": []}
    assert remove_idempotent.get_status() is True, remove_idempotent.get_message()
    assert (
        remove_idempotent.get_message() == "Category contains none of these endpoints"
    )
    assert remove_idempotent.get_summary() == {"updated": [], "ignored": [endpoint]}
