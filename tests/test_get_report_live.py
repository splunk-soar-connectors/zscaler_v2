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


def test_get_report_live_fetches_full_legacy_report(
    connector_app: App,
    build_soar_action_input: Callable[..., dict[str, Any]],
) -> None:
    file_hash = "1043ca3fc2e83f0c6f100e46d2ea16be"  # pragma: allowlist secret
    input_data = build_soar_action_input(
        action="get_report",
        parameters={"file_hash": file_hash},
    )
    connector_app.handle(json.dumps(input_data))

    result = connector_app.actions_manager.get_action_results()[-1]
    assert result.get_status() is True, result.get_message()
    assert (
        result.get_message()
        == "Sandbox report successfully fetched for the provided md5 hash"
    )
    rows = result.get_data()
    assert len(rows) == 1
    assert isinstance(rows[0]["Full Details"], dict)
    assert set(rows[0]["Full Details"]["Summary"]) == {"Message", "Status"}


def test_get_report_rejects_invalid_md5_without_api_request(
    connector_app: App,
    build_soar_action_input: Callable[..., dict[str, Any]],
) -> None:
    input_data = build_soar_action_input(
        action="get_report",
        parameters={"file_hash": "not-an-md5"},
    )
    connector_app.handle(json.dumps(input_data))

    result = connector_app.actions_manager.get_action_results()[-1]
    assert result.get_status() is False
    assert result.get_message() == "Action failure in get report: Invalid MD5 hash"
