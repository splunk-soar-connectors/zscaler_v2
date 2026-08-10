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
from typing import Any

import pytest
from pydantic import ValidationError
from soar_sdk.app import App

from src.actions.make_request import ZscalerMakeRequestParams
from src.app import create_zscaler_soar_connector_app


def _params(**overrides: Any) -> ZscalerMakeRequestParams:
    values = {
        "http_method": "GET",
        "endpoint": "/zia/api/v1/status",
        "verify_ssl": True,
    }
    values.update(overrides)
    return ZscalerMakeRequestParams(**values)


def test_make_request_normalizes_method_and_relative_zia_path() -> None:
    params = _params(http_method=" get ", endpoint="zia/api/v1/status")

    assert params.http_method == "GET"
    assert params.endpoint == "/zia/api/v1/status"
    assert params.timeout == 240
    assert params.verify_ssl is True


def test_make_request_parses_supported_parameter_encodings() -> None:
    params = _params(
        headers='{"X-Request-Reason": "validation"}',
        query_parameters="?pageSize=1&customOnly=true",
        body='{"urls": ["example.com"]}',
    )

    assert params.parsed_headers() == {"X-Request-Reason": "validation"}
    assert params.parsed_query_parameters() == {
        "pageSize": ["1"],
        "customOnly": ["true"],
    }
    assert params.parsed_body() == {"urls": ["example.com"]}


@pytest.mark.parametrize(
    "endpoint",
    [
        "https://api.zsapi.net/zia/api/v1/status",
        "/zpa/mgmtconfig/v1/admin/customers",
        "/zscsb/submit",
        "/zia/api/v1/status?details=true",
        "/zia/api/v1/status#fragment",
        "/zia/api/v1/../adminUsers",
        "/zia/api/v1/%252e%252e/adminUsers",
        "/zia/api/v1//status",
        "/zia\\api\\v1\\status",
    ],
)
def test_make_request_rejects_unsafe_or_out_of_scope_endpoints(
    endpoint: str,
) -> None:
    with pytest.raises(ValidationError, match="endpoint"):
        _params(endpoint=endpoint)


@pytest.mark.parametrize(
    "headers",
    [
        '["not", "an", "object"]',
        '{"X-Numeric": 1}',
        '{"Authorization": "Bearer caller-token"}',
        '{"host": "example.invalid"}',
        '{"X-Partner-ID": "caller-partner"}',
    ],
)
def test_make_request_rejects_invalid_or_sdk_controlled_headers(
    headers: str,
) -> None:
    with pytest.raises(ValidationError, match="headers"):
        _params(headers=headers)


@pytest.mark.parametrize(
    "query_parameters",
    [
        "[1, 2]",
        "{invalid-json}",
        '{"api_token": "caller-token"}',
        "access_token=caller-token",
        "missing-separator",
    ],
)
def test_make_request_rejects_invalid_or_credential_query_parameters(
    query_parameters: str,
) -> None:
    with pytest.raises(ValidationError, match="query_parameters"):
        _params(query_parameters=query_parameters)


@pytest.mark.parametrize("body", ["{invalid-json}", ""])
def test_make_request_body_validation(body: str) -> None:
    if body:
        with pytest.raises(ValidationError, match="body"):
            _params(body=body)
    else:
        assert _params(body=body).parsed_body() is None


@pytest.mark.parametrize("timeout", [0, 241, -1])
def test_make_request_rejects_timeout_outside_connector_bounds(timeout: int) -> None:
    with pytest.raises(ValidationError, match="timeout"):
        _params(timeout=timeout)


def test_make_request_requires_tls_verification() -> None:
    with pytest.raises(ValidationError, match="verify_ssl must be true"):
        _params(verify_ssl=False)


def test_make_request_invalid_endpoint_fails_before_authentication(
    connector_app: App,
) -> None:
    action = connector_app.get_actions()["make_request"]

    assert (
        action(
            params={
                "http_method": "GET",
                "endpoint": "https://example.invalid/zia/api/v1/status",
                "verify_ssl": True,
            }
        )
        is False
    )

    result = connector_app.actions_manager.get_action_results()[-1]
    assert result.get_status() is False
    assert "endpoint must be a relative ZIA API path" in result.get_message()


def test_make_request_uses_canonical_metadata_and_asset_lock() -> None:
    app = create_zscaler_soar_connector_app()
    action = next(
        action
        for action in app.actions_manager.get_actions_meta_list()
        if action.identifier == "make_request"
    )
    serialized = action.model_dump()

    assert action.action == "make request"
    assert action.read_only is False
    assert serialized["lock"] == {"enabled": True, "concurrency": False}
    outputs = {
        output["data_path"]: output["data_type"] for output in serialized["output"]
    }
    assert outputs["action_result.data.*.status_code"] == "numeric"
    assert outputs["action_result.data.*.response_body"] == "string"
