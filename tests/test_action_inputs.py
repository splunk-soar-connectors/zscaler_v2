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
import pytest

from src.actions._inputs import ip_values, url_values


def test_url_values_strip_protocol_case_insensitively() -> None:
    assert url_values(
        "HTTP://one.example, HtTpS://two.example/path, three.example"
    ) == ["one.example", "two.example/path", "three.example"]


def test_ip_values_accept_ipv4_and_ipv6_without_rewriting() -> None:
    assert ip_values("192.0.2.1, 2001:0db8::1") == ["192.0.2.1", "2001:0db8::1"]


@pytest.mark.parametrize("value", ["example.com", "HTTP://192.0.2.1", "300.1.1.1"])
def test_ip_values_reject_non_ip_values(value: str) -> None:
    with pytest.raises(ValueError, match="Invalid IP address"):
        ip_values(value)
