# Copyright (c) 2026 Splunk Inc.
# Licensed under the Apache License, Version 2.0
import json
from collections.abc import Callable
from typing import Any

from soar_sdk.app import App
from src.asset import Asset
from src.zscaler_client import get_client

_VALUES = ["papp-38277-remove-category.example", "203.0.113.199"]
_PARENT_VALUES = ["papp-38277-remove-parent.example", "203.0.113.200"]


def test_remove_category_destination_live_supports_mixed_values(
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
        prepared, _, error = client.zia.url_categories.add_urls_to_category(
            category_id,
            configuredName=configured_name,
            urls=_VALUES,
            dbCategorizedUrls=_PARENT_VALUES,
        )
        assert error is None
        assert prepared is not None
        activated, _, error = client.zia.activate.activate()
        assert error is None
        assert activated is not None
    try:
        connector_app.handle(
            json.dumps(
                build_live_soar_action_input(
                    action="remove_category_destination",
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
    assert all(value not in result.get_data()[0]["urls"] for value in _VALUES)
    assert all(
        value not in result.get_data()[0]["dbCategorizedUrls"]
        for value in _PARENT_VALUES
    )
