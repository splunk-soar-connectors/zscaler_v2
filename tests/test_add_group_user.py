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
from zscaler.zia.models.user_management import Groups, UserManagement

from src.actions.add_group_user import (
    _require_visible_user_name,
    _user_update_payload,
)


def test_user_update_payload_does_not_replay_password() -> None:
    user = UserManagement(
        {
            "id": 123,
            "name": "Test User",
            "password": "not-for-update",  # pragma: allowlist secret
            "groups": [{"id": 10, "name": "Existing"}],
        }
    )
    target_group = Groups({"id": 20, "name": "Target"})

    payload = _user_update_payload(user, target_group)

    assert "password" not in payload
    assert [group["id"] for group in payload["groups"]] == [10, 20]


@pytest.mark.parametrize("name", [None, "", "x" * 128])
def test_user_update_rejects_unusable_names(name: str | None) -> None:
    with pytest.raises(RuntimeError, match="ZIA API role"):
        _require_visible_user_name(name)


def test_user_update_accepts_visible_name() -> None:
    _require_visible_user_name("Test User")
