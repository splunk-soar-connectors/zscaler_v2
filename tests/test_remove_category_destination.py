# Copyright (c) 2026 Splunk Inc.
# Licensed under the Apache License, Version 2.0
import json
from collections.abc import Callable
from typing import Any

from soar_sdk.app import App
from src.app import create_zscaler_soar_connector_app


def test_remove_category_destination_requires_a_destination(
    connector_app: App, build_soar_action_input: Callable[..., dict[str, Any]]
) -> None:
    connector_app.handle(
        json.dumps(
            build_soar_action_input(
                action="remove_category_destination",
                parameters={"category_id": "CUSTOM_01"},
            )
        )
    )
    result = connector_app.actions_manager.get_action_results()[-1]
    assert result.get_status() is False
    assert "Provide at least one value" in result.get_message()


def test_remove_category_destination_replaces_old_actions() -> None:
    actions = {
        action.identifier: action
        for action in create_zscaler_soar_connector_app().actions_manager.get_actions_meta_list()
    }
    assert "remove_category_ip" not in actions
    assert "remove_category_url" not in actions
    action = actions["remove_category_destination"]
    assert action.read_only is False
    assert action.model_dump()["lock"] == {"enabled": True, "concurrency": False}
