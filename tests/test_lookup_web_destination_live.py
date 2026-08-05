# Copyright (c) 2026 Splunk Inc.
# Licensed under the Apache License, Version 2.0
import json
from collections.abc import Callable
from typing import Any

from soar_sdk.app import App


def test_lookup_web_destination_live_preserves_arrays_and_normalizes_protocol(
    connector_app: App,
    build_live_soar_action_input: Callable[..., dict[str, Any]],
) -> None:
    connector_app.handle(
        json.dumps(
            build_live_soar_action_input(
                action="lookup_web_destination",
                parameters={"destinations": "HTTPS://example.com, 8.8.8.8"},
            )
        )
    )
    result = connector_app.actions_manager.get_action_results()[-1]
    assert result.get_status() is True, result.get_message()
    rows = result.get_data()
    assert {row["destination"] for row in rows} == {"example.com", "8.8.8.8"}
    assert all(isinstance(row["blocklisted"], bool) for row in rows)
    assert all(isinstance(row["urlClassifications"], list) for row in rows)
    assert all(
        isinstance(row["urlClassificationsWithSecurityAlert"], list) for row in rows
    )
