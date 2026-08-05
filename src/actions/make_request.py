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
from typing import Any
from urllib.parse import parse_qs, unquote, urlsplit

from pydantic import field_validator
from soar_sdk.action_results import MakeRequestOutput
from soar_sdk.exceptions import ActionFailure
from soar_sdk.params import MakeRequestParams, Param

from ..asset import Asset
from ..zscaler_client import DEFAULT_REQUEST_TIMEOUT, get_client

_ALLOWED_METHODS = frozenset(
    {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}
)
_PROTECTED_HEADERS = frozenset(
    {
        "authorization",
        "content-length",
        "cookie",
        "host",
        "proxy-authorization",
        "transfer-encoding",
        "x-api-key",
        "x-partner-id",
    }
)
_PROTECTED_QUERY_PARAMETERS = frozenset(
    {
        "access_token",
        "api_key",
        "api_token",
        "client_secret",
    }
)
_ZIA_API_PREFIX = "/zia/api/v1"


def _load_json(value: str, parameter: str) -> Any:
    try:
        return json.loads(value)
    except (json.JSONDecodeError, TypeError) as exc:
        raise ValueError(f"{parameter} must be valid JSON") from exc


def _parse_headers(value: str | None) -> dict[str, str]:
    if value is None or not value.strip():
        return {}

    parsed = _load_json(value, "headers")
    if not isinstance(parsed, dict):
        raise ValueError("headers must be a JSON object")
    if not all(
        isinstance(key, str) and isinstance(item, str) for key, item in parsed.items()
    ):
        raise ValueError("headers must contain only string keys and string values")

    protected = sorted(key for key in parsed if key.casefold() in _PROTECTED_HEADERS)
    if protected:
        raise ValueError(
            "headers cannot override SDK-controlled header(s): " + ", ".join(protected)
        )
    return parsed


def _parse_query_parameters(value: str | None) -> dict[str, Any]:
    if value is None or not value.strip():
        return {}

    raw_value = value.strip()
    try:
        parsed: Any = json.loads(raw_value)
    except json.JSONDecodeError as exc:
        if raw_value.startswith(("{", "[")):
            raise ValueError("query_parameters must be valid JSON") from exc
        try:
            parsed = parse_qs(
                raw_value.removeprefix("?"),
                keep_blank_values=True,
                strict_parsing=True,
            )
        except ValueError as query_error:
            raise ValueError(
                "query_parameters must be a JSON object or query string"
            ) from query_error

    if not isinstance(parsed, dict):
        raise ValueError("query_parameters must be a JSON object or query string")
    if not all(isinstance(key, str) for key in parsed):
        raise ValueError("query_parameters must contain only string keys")

    protected = sorted(
        key for key in parsed if key.casefold() in _PROTECTED_QUERY_PARAMETERS
    )
    if protected:
        raise ValueError(
            "query_parameters cannot contain credential parameter(s): "
            + ", ".join(protected)
        )
    return parsed


def _parse_body(value: str | None) -> Any:
    if value is None or not value.strip():
        return None
    return _load_json(value, "body")


class ZscalerMakeRequestParams(MakeRequestParams):
    endpoint: str = Param(
        required=True,
        description=(
            "ZIA API path relative to the OneAPI gateway, for example "
            "'/zia/api/v1/status'. Do not include a base URL or query string."
        ),
    )
    timeout: int = Param(
        required=False,
        default=DEFAULT_REQUEST_TIMEOUT,
        description=(
            "Request timeout in seconds. Must be between 1 and 240. Default is 240."
        ),
    )
    verify_ssl: bool = Param(
        required=False,
        default=True,
        description="Verify the TLS certificate. This must be true.",
    )

    @field_validator("http_method")
    @classmethod
    def validate_http_method(cls, value: str) -> str:
        method = value.strip().upper()
        if method not in _ALLOWED_METHODS:
            raise ValueError(f"Unsupported HTTP method: {value}")
        return method

    @field_validator("endpoint")
    @classmethod
    def validate_endpoint(cls, value: str) -> str:
        endpoint = value.strip()
        parsed = urlsplit(endpoint)
        if parsed.scheme or parsed.netloc:
            raise ValueError("endpoint must be a relative ZIA API path, not a URL")
        if parsed.query or parsed.fragment:
            raise ValueError(
                "endpoint cannot contain a query string or fragment; use query_parameters"
            )
        if "\\" in endpoint:
            raise ValueError("endpoint cannot contain backslashes")

        endpoint = f"/{parsed.path.lstrip('/')}"
        if "//" in endpoint:
            raise ValueError("endpoint cannot contain empty path segments")

        decoded_endpoint = endpoint
        for _ in range(2):
            decoded_endpoint = unquote(decoded_endpoint)
        if any(segment in {".", ".."} for segment in decoded_endpoint.split("/")):
            raise ValueError("endpoint cannot contain path traversal segments")

        if endpoint != _ZIA_API_PREFIX and not endpoint.startswith(
            f"{_ZIA_API_PREFIX}/"
        ):
            raise ValueError("endpoint must target /zia/api/v1")
        return endpoint

    @field_validator("headers")
    @classmethod
    def validate_headers(cls, value: str | None) -> str | None:
        _parse_headers(value)
        return value

    @field_validator("query_parameters")
    @classmethod
    def validate_query_parameters(cls, value: str | None) -> str | None:
        _parse_query_parameters(value)
        return value

    @field_validator("body")
    @classmethod
    def validate_body(cls, value: str | None) -> str | None:
        _parse_body(value)
        return value

    @field_validator("timeout")
    @classmethod
    def validate_timeout(cls, value: int) -> int:
        if not 1 <= value <= DEFAULT_REQUEST_TIMEOUT:
            raise ValueError(
                f"timeout must be between 1 and {DEFAULT_REQUEST_TIMEOUT} seconds"
            )
        return value

    @field_validator("verify_ssl")
    @classmethod
    def validate_verify_ssl(cls, value: bool) -> bool:
        if value is not True:
            raise ValueError("verify_ssl must be true")
        return value

    def parsed_headers(self) -> dict[str, str]:
        return _parse_headers(self.headers)

    def parsed_query_parameters(self) -> dict[str, Any]:
        return _parse_query_parameters(self.query_parameters)

    def parsed_body(self) -> Any:
        return _parse_body(self.body)


def make_request(params: ZscalerMakeRequestParams, asset: Asset) -> MakeRequestOutput:
    """Send an authenticated request to a ZIA OneAPI endpoint."""
    body = params.parsed_body()

    try:
        with get_client(asset, request_timeout=params.timeout) as client:
            executor = client.get_request_executor()
            request, request_error = executor.create_request(
                method=params.http_method,
                endpoint=params.endpoint,
                headers=params.parsed_headers(),
                params=params.parsed_query_parameters(),
                body=body,
            )
            if request_error is not None:
                raise RuntimeError(f"Unable to create Zscaler request: {request_error}")

            if body is None:
                request.pop("json", None)

            response, response_error = executor.execute(
                request, return_raw_response=True
            )
            if response_error is not None:
                raise RuntimeError(f"Zscaler API error: {response_error}")
            if response is None:
                raise RuntimeError("Zscaler API returned no response")
    except Exception as exc:
        raise ActionFailure(f"Request failed: {exc}") from exc

    return MakeRequestOutput(
        status_code=response.status_code,
        response_body=response.text,
    )
