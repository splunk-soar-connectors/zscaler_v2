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

_VALUES = ["papp-38277-category.example", "203.0.113.197"]
_PARENT_VALUES = ["papp-38277-parent-category.example", "203.0.113.198"]


def test_add_category_destination_live_supports_mixed_values(
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
        category = next(
            item
            for item in response.get_results()
            if isinstance(item, dict) and item.get("customCategory", False)
        )
        category_id = category["id"]
        configured_name = category["configuredName"]
    try:
        connector_app.handle(
            json.dumps(
                build_live_soar_action_input(
                    action="add_category_destination",
                    parameters={
                        "category_id": category_id,
                        "destinations": ", ".join(_VALUES),
                        "retaining_parent_category_destinations": ", ".join(
                            _PARENT_VALUES
                        ),
                    },
                )
            )
        )
        result = connector_app.actions_manager.get_action_results()[-1]
    finally:
        with get_client(asset) as client:
            client.zia.url_categories.delete_urls_from_category(
                category_id,
                configuredName=configured_name,
                urls=_VALUES,
                dbCategorizedUrls=_PARENT_VALUES,
            )
            client.zia.activate.activate()
    assert result.get_status() is True, result.get_message()
    assert all(value in result.get_data()[0]["urls"] for value in _VALUES)
    assert all(
        value in result.get_data()[0]["dbCategorizedUrls"] for value in _PARENT_VALUES
    )
