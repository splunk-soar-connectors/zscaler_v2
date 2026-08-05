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

_TEST_URL = "papp-38277-block.example"
_TEST_IP = "192.0.2.77"


def test_block_web_destination_live_handles_mixed_inputs_and_is_idempotent(
    connector_app: App,
    build_live_soar_action_input: Callable[..., dict[str, Any]],
    live_asset_config: dict[str, str],
) -> None:
    asset = Asset.model_validate(live_asset_config)
    with get_client(asset) as client:
        initial, _response, error = client.zia.security_policy_settings.get_blacklist()
        assert error is None
        assert initial is not None
        assert _TEST_URL not in initial.blacklist_urls
        assert _TEST_IP not in initial.blacklist_urls

    results = []
    try:
        for destinations in (
            f"HTTPS://{_TEST_URL}, {_TEST_IP}, {_TEST_URL}",
            f"{_TEST_URL}, {_TEST_IP}",
        ):
            connector_app.handle(
                json.dumps(
                    build_live_soar_action_input(
                        action="block_web_destination",
                        parameters={"destinations": destinations},
                    )
                )
            )
            results.append(connector_app.actions_manager.get_action_results()[-1])

        with get_client(asset) as client:
            changed, _response, error = (
                client.zia.security_policy_settings.get_blacklist()
            )
            assert error is None
            assert changed is not None
            assert _TEST_URL in changed.blacklist_urls
            assert _TEST_IP in changed.blacklist_urls
    finally:
        with get_client(asset) as client:
            cleaned, _response, error = (
                client.zia.security_policy_settings.delete_urls_from_blacklist(
                    [_TEST_URL, _TEST_IP]
                )
            )
            assert error is None
            assert cleaned is not None
            activation, _response, error = client.zia.activate.activate()
            assert error is None
            assert activation is not None

    first, second = results
    assert first.get_status() is True, first.get_message()
    assert first.get_summary() == {"updated": [_TEST_URL, _TEST_IP], "ignored": []}
    assert second.get_status() is True, second.get_message()
    assert second.get_message() == "Blocklist contains all of these destinations"
    assert second.get_summary() == {
        "updated": [],
        "ignored": [_TEST_URL, _TEST_IP],
    }
