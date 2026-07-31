# Copyright (c) 2026 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
import json
from collections.abc import Callable
from typing import Any

from soar_sdk.app import App
from src.asset import Asset
from src.zscaler_client import get_client

_TEST_URL = "papp-38277-unallow.example"


def test_unallow_url_live_is_reversible_and_idempotent(
    connector_app: App,
    build_live_soar_action_input: Callable[..., dict[str, Any]],
    live_asset_config: dict[str, str],
) -> None:
    asset = Asset.model_validate(live_asset_config)
    with get_client(asset) as client:
        initial, _, error = client.zia.security_policy_settings.get_whitelist()
        assert error is None
        assert initial is not None
        assert _TEST_URL not in initial.whitelist_urls
        prepared, _, error = client.zia.security_policy_settings.add_urls_to_whitelist(
            [_TEST_URL]
        )
        assert error is None
        assert prepared is not None
        activated, _, error = client.zia.activate.activate()
        assert error is None
        assert activated is not None
    try:
        for value in (f"https://{_TEST_URL}", _TEST_URL):
            connector_app.handle(
                json.dumps(
                    build_live_soar_action_input(
                        action="unallow_url", parameters={"url": value}
                    )
                )
            )
        first, second = connector_app.actions_manager.get_action_results()[-2:]
    finally:
        with get_client(asset) as client:
            client.zia.security_policy_settings.delete_urls_from_whitelist([_TEST_URL])
            client.zia.activate.activate()
    assert first.get_status() is True, first.get_message()
    assert first.get_summary() == {"updated": [_TEST_URL], "ignored": []}
    assert second.get_status() is True, second.get_message()
    assert second.get_message() == "Allowlist contains none of these endpoints"
