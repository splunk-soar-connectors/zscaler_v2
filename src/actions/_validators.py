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


def validate_web_destination(value: str) -> str:
    scheme, separator, remainder = value.partition("://")
    normalized_value = value
    if separator:
        if scheme.casefold() not in {"http", "https"}:
            raise ValueError(f"Unsupported web destination scheme in value: {value}")
        normalized_value = remainder

    if not normalized_value:
        raise ValueError("Web destination cannot be empty")
    if any(character.isspace() for character in normalized_value):
        raise ValueError(
            f"Web destination cannot contain whitespace: {normalized_value}"
        )
    if len(normalized_value) > 1024:
        raise ValueError(
            "Max allowed length for each web destination is 1024 characters"
        )

    try:
        ipaddress.ip_address(normalized_value)
    except ValueError as exc:
        octets = normalized_value.split(".")
        if len(octets) == 4 and all(octet.isdigit() for octet in octets):
            raise ValueError(f"Invalid IP address value: {normalized_value}") from exc

    return normalized_value
