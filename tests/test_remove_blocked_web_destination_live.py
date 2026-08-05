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

_TEST_URL = "papp-38277-remove-block.example"
_TEST_IP = "192.0.2.81"


def test_remove_blocked_web_destination_live_handles_mixed_inputs(
    connector_app: App,
    build_live_soar_action_input: Callable[..., dict[str, Any]],
    live_asset_config: dict[str, str],
) -> None:
    asset = Asset.model_validate(live_asset_config)
    with get_client(asset) as client:
        prepared, _, error = client.zia.security_policy_settings.add_urls_to_blacklist(
            [_TEST_URL, _TEST_IP]
        )
        assert error is None
        assert prepared is not None
        activated, _, error = client.zia.activate.activate()
        assert error is None
        assert activated is not None
    try:
        for values in (f"HTTPS://{_TEST_URL}, {_TEST_IP}", f"{_TEST_URL}, {_TEST_IP}"):
            connector_app.handle(
                json.dumps(
                    build_live_soar_action_input(
                        action="remove_blocked_web_destination",
                        parameters={"destinations": values},
                    )
                )
            )
        first, second = connector_app.actions_manager.get_action_results()[-2:]
    finally:
        with get_client(asset) as client:
            client.zia.security_policy_settings.delete_urls_from_blacklist(
                [_TEST_URL, _TEST_IP]
            )
            client.zia.activate.activate()
    assert first.get_status() is True, first.get_message()
    assert first.get_summary() == {"updated": [_TEST_URL, _TEST_IP], "ignored": []}
    assert second.get_status() is True, second.get_message()
    assert second.get_message() == "Blocklist contains none of these destinations"
    assert second.get_summary() == {"updated": [], "ignored": [_TEST_URL, _TEST_IP]}
