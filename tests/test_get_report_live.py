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
from pathlib import Path
from typing import Any
from uuid import uuid4

from soar_sdk.app import App

from src.asset import Asset
from src.zscaler_client import get_client

_SANDBOX_TEST_FILE = (
    Path(__file__).resolve().parents[2]
    / "app-tests"
    / "resources"
    / "files"
    / "test_dll.dll"
)


def test_get_report_live_fetches_full_legacy_report(
    connector_app: App,
    build_live_soar_action_input: Callable[..., dict[str, Any]],
    live_asset_config: dict[str, str],
) -> None:
    assert _SANDBOX_TEST_FILE.is_file()
    asset = Asset.model_validate(live_asset_config)
    with get_client(asset) as client:
        _submission, response, error = client.zia.sandbox.submit_file(
            file_path=str(_SANDBOX_TEST_FILE),
            force=False,
        )
        assert error is None
        assert response is not None
        submission = response.get_body()
        assert isinstance(submission, dict)
        assert submission.get("code") == 200
        file_hash = submission.get("md5")
        assert isinstance(file_hash, str)

    input_data = build_live_soar_action_input(
        action="get_report",
        parameters={"file_hash": file_hash},
    )
    connector_app.handle(json.dumps(input_data))

    result = connector_app.actions_manager.get_action_results()[-1]
    assert result.get_status() is True, result.get_message()
    assert (
        result.get_message()
        == "Sandbox report successfully fetched for the provided MD5 hash"
    )
    rows = result.get_data()
    assert len(rows) == 1
    assert isinstance(rows[0]["Full Details"], dict)
    assert "Status" in rows[0]["Full Details"]["Summary"]


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


def test_get_report_live_rejects_unknown_md5(
    connector_app: App,
    build_live_soar_action_input: Callable[..., dict[str, Any]],
) -> None:
    input_data = build_live_soar_action_input(
        action="get_report",
        parameters={"file_hash": uuid4().hex},
    )
    connector_app.handle(json.dumps(input_data))

    result = connector_app.actions_manager.get_action_results()[-1]
    assert result.get_status() is False
    assert "Content lookup failed." in result.get_message()
