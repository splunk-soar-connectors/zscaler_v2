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
from pathlib import Path

import pytest
from soar_sdk.models.vault_attachment import VaultAttachment

from src.actions.submit_file import (
    SubmitFileOutput,
    _redact_sandbox_token,
    _select_vault_attachment,
    _submission_message,
)


def _attachment(*, attachment_id: int, path: Path) -> VaultAttachment:
    return VaultAttachment(
        id=attachment_id,
        container="test container",
        create_time="2026-07-30T00:00:00Z",
        name=path.name,
        user="test user",
        vault_document=attachment_id,
        hash="test hash",
        vault_id="test vault id",
        size=0,
        path=str(path),
        container_id=1,
    )


def test_select_vault_attachment_rejects_missing_file() -> None:
    with pytest.raises(
        RuntimeError,
        match="Vault file could not be found with the supplied vault ID",
    ):
        _select_vault_attachment([])


def test_select_vault_attachment_deterministically_accepts_duplicate_records(
    tmp_path: Path,
) -> None:
    older = _attachment(attachment_id=10, path=tmp_path / "older.bin")
    newer = _attachment(attachment_id=20, path=tmp_path / "newer.bin")

    assert _select_vault_attachment([newer, older]) is older


@pytest.mark.parametrize(
    ("submission", "expected"),
    [
        (
            {"code": 200, "message": "/submit response OK"},
            "Successfully submitted the file to Sandbox",
        ),
        (
            {
                "code": 200,
                "sandboxSubmission": "Submitted",
                "message": "Queued for analysis",
            },
            "Status Code: 200. Data from server: Submitted. Queued for analysis",
        ),
        (
            {"code": 200, "sandboxSubmission": "Virus", "message": "virus"},
            "Status Code: 200. Data from server: Virus",
        ),
        ({"code": 200}, "Successfully submitted the file to Sandbox"),
    ],
)
def test_submission_message_preserves_response_details(
    submission: dict[str, object], expected: str
) -> None:
    assert _submission_message(submission) == expected


def test_submit_file_output_preserves_variable_response_fields() -> None:
    output = SubmitFileOutput(
        code=200,
        message="Queued",
        requestId="sandbox-request-1",
    )

    assert output.model_dump(exclude_none=True) == {
        "code": 200.0,
        "message": "Queued",
        "requestId": "sandbox-request-1",
    }


@pytest.mark.parametrize("parameter_name", ["api_token", "API_TOKEN"])
def test_sandbox_token_is_redacted_from_sdk_errors(parameter_name: str) -> None:
    error = (
        "HTTPSConnectionPool failed with url: "
        f"/zscsb/submit?force=0&{parameter_name}=sensitive%2Ftoken "
        "(Caused by connection error)"
    )

    safe_error = _redact_sandbox_token(error)

    assert "sensitive" not in safe_error
    assert f"{parameter_name}=<redacted>" in safe_error
    assert "force=0" in safe_error
