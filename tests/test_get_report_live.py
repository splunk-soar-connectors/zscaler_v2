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
from uuid import uuid4

from soar_sdk.app import App

from tests.conftest import SANDBOX_TEST_FILE_MD5


def test_get_report_live_fetches_connector_fixture_report(
    connector_app: App,
    build_live_soar_action_input: Callable[..., dict[str, Any]],
    sandbox_live_asset_config: dict[str, str],
) -> None:
    del sandbox_live_asset_config
    connector_app.handle(
        json.dumps(
            build_live_soar_action_input(
                action="get_report",
                parameters={"file_hash": SANDBOX_TEST_FILE_MD5},
            )
        )
    )

    result = connector_app.actions_manager.get_action_results()[-1]
    assert result.get_status() is True, result.get_message()
    assert (
        result.get_message()
        == "Sandbox report successfully fetched for the provided MD5 hash"
    )
    rows = result.get_data()
    assert len(rows) == 1
    full_details = rows[0]["Full Details"]
    assert isinstance(full_details, dict)
    assert full_details["FileProperties"]["MD5"].casefold() == SANDBOX_TEST_FILE_MD5


def test_get_report_live_rejects_unknown_md5(
    connector_app: App,
    build_live_soar_action_input: Callable[..., dict[str, Any]],
    sandbox_live_asset_config: dict[str, str],
) -> None:
    del sandbox_live_asset_config
    connector_app.handle(
        json.dumps(
            build_live_soar_action_input(
                action="get_report",
                parameters={"file_hash": uuid4().hex},
            )
        )
    )

    result = connector_app.actions_manager.get_action_results()[-1]
    assert result.get_status() is False
    assert "Content lookup failed." in result.get_message()
