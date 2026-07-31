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
import ipaddress

from soar_sdk.abstract import SOARClient
from soar_sdk.exceptions import ActionFailure


def comma_separated_values(value: str | None) -> list[str]:
    return [item.strip() for item in (value or "").split(",") if item.strip()]


def url_values(value: str | None) -> list[str]:
    values = comma_separated_values(value)
    normalized: list[str] = []
    for item in values:
        scheme, separator, remainder = item.partition("://")
        if separator and scheme.casefold() in {"http", "https"}:
            normalized.append(remainder)
        else:
            normalized.append(item)
    return normalized


def ip_values(value: str | None) -> list[str]:
    values = comma_separated_values(value)
    invalid: list[str] = []
    for item in values:
        try:
            ipaddress.ip_address(item)
        except ValueError:
            invalid.append(item)
    if invalid:
        raise ValueError(f"Invalid IP address value(s): {', '.join(invalid)}")
    return values


def validated_ip_values(value: str | None, soar: SOARClient) -> list[str]:
    try:
        return ip_values(value)
    except ValueError as exc:
        message = str(exc)
        soar.set_message(message)
        raise ActionFailure(message) from exc
