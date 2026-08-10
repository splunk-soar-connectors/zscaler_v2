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
from pydantic import ValidationError

from src.asset import Asset


def _asset(vanity_domain: str) -> Asset:
    return Asset.model_validate(
        {
            "vanity_domain": vanity_domain,
            "client_id": "test-client",
            "client_secret": "test-secret",  # pragma: allowlist secret
        }
    )


@pytest.mark.parametrize(
    "vanity_domain",
    ["dev-new-soar-splunk", "tenant1", "A"],
)
def test_asset_accepts_vanity_domain_prefix(vanity_domain: str) -> None:
    assert _asset(vanity_domain).vanity_domain == vanity_domain


@pytest.mark.parametrize(
    "vanity_domain",
    [
        "https://tenant",
        "user@tenant",
        "tenant.zslogin.net",
        "-tenant",
        "tenant-",
        " tenant ",
        "",
    ],
)
def test_asset_rejects_values_that_are_not_vanity_domain_prefixes(
    vanity_domain: str,
) -> None:
    with pytest.raises(ValidationError, match="must be a domain prefix"):
        _asset(vanity_domain)
