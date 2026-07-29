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

from soar_sdk.app import App

_SANDBOX_TEST_FILE = (
    Path(__file__).resolve().parents[2]
    / "app-tests"
    / "resources"
    / "files"
    / "test_dll.dll"
)
_EXPECTED_MD5 = "a8f53963f2b499e50faf621f7c117f96"  # pragma: allowlist secret


def test_submit_file_live_uses_vault_attachment(
    connector_app: App,
    build_soar_action_input: Callable[..., dict[str, Any]],
) -> None:
    assert _SANDBOX_TEST_FILE.is_file(), (
        f"Sandbox test fixture not found: {_SANDBOX_TEST_FILE}"
    )
    vault_id = connector_app.soar_client.vault.add_attachment(
        container_id=456,
        file_location=str(_SANDBOX_TEST_FILE),
        file_name=_SANDBOX_TEST_FILE.name,
    )
    input_data = build_soar_action_input(
        action="submit_file",
        parameters={"vault_id": vault_id, "force": False},
    )

    connector_app.handle(json.dumps(input_data))

    result = connector_app.actions_manager.get_action_results()[-1]
    assert result.get_status() is True, result.get_message()
    assert result.get_message() == "Successfully submitted the file to Sandbox"
    rows = result.get_data()
    assert len(rows) == 1
    assert rows[0]["code"] == 200
    assert rows[0]["md5"].casefold() == _EXPECTED_MD5


def test_submit_file_requires_sandbox_token(
    connector_app: App,
    build_soar_action_input: Callable[..., dict[str, Any]],
) -> None:
    input_data = build_soar_action_input(
        action="submit_file",
        parameters={"vault_id": "unused"},
    )
    input_data["config"].pop("sandbox_token", None)

    connector_app.handle(json.dumps(input_data))

    result = connector_app.actions_manager.get_action_results()[-1]
    assert result.get_status() is False
    assert result.get_message() == (
        "Action failure in submit file: Sandbox API token is required to submit a file"
    )


def test_submit_file_requires_sandbox_cloud(
    connector_app: App,
    build_soar_action_input: Callable[..., dict[str, Any]],
) -> None:
    input_data = build_soar_action_input(
        action="submit_file",
        parameters={"vault_id": "unused"},
    )
    input_data["config"].pop("sandbox_cloud", None)

    connector_app.handle(json.dumps(input_data))

    result = connector_app.actions_manager.get_action_results()[-1]
    assert result.get_status() is False
    assert result.get_message() == (
        "Action failure in submit file: Sandbox cloud is required to submit a file"
    )
