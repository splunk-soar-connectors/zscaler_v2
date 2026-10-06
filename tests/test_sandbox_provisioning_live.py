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
import socket
from pathlib import Path

from src.actions.submit_file import _redact_sandbox_token
from src.asset import Asset
from src.zscaler_client import get_client
from tests.conftest import SANDBOX_TEST_FILE_MD5

_PROBE_REQUEST_TIMEOUT = 30


def _sanitize_probe_exception(exc: Exception, asset: Asset) -> str:
    message = str(exc)
    for secret in (asset.client_id, asset.client_secret, asset.sandbox_token):
        if secret:
            message = message.replace(secret, "<redacted>")
    return f"{type(exc).__name__}: {message}"


def test_sandbox_submission_hostname_resolves(
    sandbox_live_asset_config: dict[str, str],
) -> None:
    sandbox_cloud = sandbox_live_asset_config["sandbox_cloud"].strip().lower()
    hostname = f"csbapi.{sandbox_cloud}.net"

    try:
        addresses = socket.getaddrinfo(
            hostname,
            443,
            type=socket.SOCK_STREAM,
        )
    except socket.gaierror as exc:
        raise AssertionError(
            f"Sandbox submission plane is not provisioned in DNS: {hostname}: {exc}"
        ) from exc

    assert addresses, f"Sandbox submission plane returned no addresses: {hostname}"


def test_sandbox_submission_api_accepts_connector_fixture(
    sandbox_live_asset_config: dict[str, str],
    sandbox_test_file: Path,
) -> None:
    asset = Asset.model_validate(sandbox_live_asset_config)
    try:
        with get_client(
            asset,
            request_timeout=_PROBE_REQUEST_TIMEOUT,
            max_retries=0,
            max_retry_seconds=0,
        ) as client:
            _submission, response, error = client.zia.sandbox.submit_file(
                file_path=str(sandbox_test_file),
                force=False,
            )
    except Exception as exc:
        raise AssertionError(
            "Sandbox token-authenticated submission probe raised "
            f"{_sanitize_probe_exception(exc, asset)}"
        ) from None

    assert error is None, (
        "Sandbox token-authenticated submission probe failed: "
        f"{_redact_sandbox_token(error)}"
    )
    assert response is not None, "Sandbox submission probe returned no response"
    raw_submission = response.get_body()
    assert isinstance(raw_submission, dict), (
        "Sandbox submission probe returned a non-object response"
    )
    assert raw_submission.get("code") == 200, (
        "Sandbox submission probe returned a non-success response: "
        f"{raw_submission.get('code')}: {raw_submission.get('message')}"
    )
    assert str(raw_submission.get("md5", "")).casefold() == SANDBOX_TEST_FILE_MD5


def test_sandbox_report_api_returns_fixture_report(
    sandbox_live_asset_config: dict[str, str],
) -> None:
    asset = Asset.model_validate(sandbox_live_asset_config)
    try:
        with get_client(
            asset,
            request_timeout=_PROBE_REQUEST_TIMEOUT,
            max_retries=0,
            max_retry_seconds=0,
        ) as client:
            _report, response, error = client.zia.sandbox.get_report(
                SANDBOX_TEST_FILE_MD5,
                report_details="full",
            )
    except Exception as exc:
        raise AssertionError(
            "OneAPI Sandbox report probe raised "
            f"{_sanitize_probe_exception(exc, asset)}"
        ) from None

    assert error is None, f"OneAPI Sandbox report probe failed: {error}"
    assert response is not None, "OneAPI Sandbox report probe returned no response"
    raw_report = response.get_body()
    assert isinstance(raw_report, dict), (
        "OneAPI Sandbox report probe returned a non-object response"
    )
    full_details = raw_report.get("Full Details")
    assert isinstance(full_details, dict), (
        "OneAPI Sandbox report is unavailable for the connector fixture: "
        f"{full_details}"
    )
    file_properties = full_details.get("FileProperties")
    assert isinstance(file_properties, dict)
    assert str(file_properties.get("MD5", "")).casefold() == SANDBOX_TEST_FILE_MD5
