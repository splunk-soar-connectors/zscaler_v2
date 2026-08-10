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
from src.asset import Asset


def test_asset_uses_oneapi_authentication_contract() -> None:
    configuration = Asset.to_json_schema()

    assert {
        "vanity_domain",
        "client_id",
        "client_secret",
        "cloud",
    } <= configuration.keys()
    assert {
        "base_url",
        "api_key",
        "username",
        "password",
        "sandbox_base_url",
        "sandbox_api_token",
        "sandbox_token",
        "sandbox_cloud",
    }.isdisjoint(configuration)

    assert configuration["vanity_domain"]["required"] is True
    assert configuration["client_id"]["required"] is True
    assert configuration["client_secret"]["required"] is True
    assert configuration["client_secret"]["data_type"] == "password"
