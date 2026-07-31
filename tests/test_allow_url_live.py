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

_TEST_URL = "papp-38277-allow.example"


def test_allow_url_live_strips_protocol_updates_and_is_idempotent(
    connector_app: App,
    build_live_soar_action_input: Callable[..., dict[str, Any]],
    live_asset_config: dict[str, str],
) -> None:
    asset = Asset.model_validate(live_asset_config)
    with get_client(asset) as client:
        initial, _response, error = client.zia.security_policy_settings.get_whitelist()
        assert error is None
        assert initial is not None
        assert _TEST_URL not in initial.whitelist_urls, (
            f"{_TEST_URL} must not exist before this test"
        )

    first_result = None
    second_result = None
    try:
        first_input = build_live_soar_action_input(
            action="allow_url", parameters={"url": f"https://{_TEST_URL}"}
        )
        connector_app.handle(json.dumps(first_input))
        first_result = connector_app.actions_manager.get_action_results()[-1]

        second_input = build_live_soar_action_input(
            action="allow_url", parameters={"url": _TEST_URL}
        )
        connector_app.handle(json.dumps(second_input))
        second_result = connector_app.actions_manager.get_action_results()[-1]

        with get_client(asset) as client:
            changed, _response, error = (
                client.zia.security_policy_settings.get_whitelist()
            )
            assert error is None
            assert changed is not None
            assert _TEST_URL in changed.whitelist_urls
    finally:
        with get_client(asset) as client:
            cleaned, _response, cleanup_error = (
                client.zia.security_policy_settings.delete_urls_from_whitelist(
                    [_TEST_URL]
                )
            )
            assert cleanup_error is None
            assert cleaned is not None
            activation, _response, activation_error = client.zia.activate.activate()
            assert activation_error is None
            assert activation is not None

    assert first_result is not None
    assert first_result.get_status() is True, first_result.get_message()
    assert _TEST_URL in first_result.get_data()[0]["whitelistUrls"]
    assert first_result.get_summary() == {"updated": [_TEST_URL], "ignored": []}

    assert second_result is not None
    assert second_result.get_status() is True, second_result.get_message()
    assert second_result.get_message() == "Allowlist contains all of these endpoints"
    assert second_result.get_summary() == {"updated": [], "ignored": [_TEST_URL]}
