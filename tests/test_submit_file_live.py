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
import os
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


def test_submit_file_live_forces_submission_and_fetches_returned_report(
    connector_app: App,
    build_live_soar_action_input: Callable[..., dict[str, Any]],
) -> None:
    assert _SANDBOX_TEST_FILE.is_file(), (
        f"Sandbox test fixture not found: {_SANDBOX_TEST_FILE}"
    )
    vault_id = connector_app.soar_client.vault.add_attachment(
        container_id=int(os.environ.get("SOAR_CONTAINER_ID", "456")),
        file_location=str(_SANDBOX_TEST_FILE),
        file_name=_SANDBOX_TEST_FILE.name,
    )
    input_data = build_live_soar_action_input(
        action="submit_file",
        parameters={"vault_id": vault_id, "force": True},
    )

    connector_app.handle(json.dumps(input_data))

    submission_result = connector_app.actions_manager.get_action_results()[-1]
    assert submission_result.get_status() is True, submission_result.get_message()
    assert (
        submission_result.get_message() == "Successfully submitted the file to Sandbox"
    )
    rows = submission_result.get_data()
    assert len(rows) == 1
    assert rows[0]["code"] == 200
    assert rows[0]["md5"].casefold() == _EXPECTED_MD5
    assert {
        "code",
        "fileType",
        "md5",
        "message",
        "sandboxSubmission",
        "virusName",
        "virusType",
    } <= rows[0].keys()

    report_input = build_live_soar_action_input(
        action="get_report",
        parameters={"file_hash": rows[0]["md5"]},
    )
    connector_app.handle(json.dumps(report_input))

    report_result = connector_app.actions_manager.get_action_results()[-1]
    assert report_result.get_status() is True, report_result.get_message()
    assert (
        report_result.get_message()
        == "Sandbox report successfully fetched for the provided MD5 hash"
    )
    reports = report_result.get_data()
    assert len(reports) == 1
    assert isinstance(reports[0]["Full Details"], dict)
    assert (
        reports[0]["Full Details"]["FileProperties"]["MD5"].casefold()
        == rows[0]["md5"].casefold()
    )


def test_submit_file_rejects_unknown_vault_id(
    connector_app: App,
    build_soar_action_input: Callable[..., dict[str, Any]],
) -> None:
    input_data = build_soar_action_input(
        action="submit_file",
        parameters={"vault_id": "does-not-exist", "force": False},
    )

    connector_app.handle(json.dumps(input_data))

    result = connector_app.actions_manager.get_action_results()[-1]
    assert result.get_status() is False
    assert "Vault file could not be found with the supplied vault ID" in (
        result.get_message()
    )


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
