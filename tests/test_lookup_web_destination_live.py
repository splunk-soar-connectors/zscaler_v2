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
from collections.abc import Callable
from typing import Any

from soar_sdk.app import App


def test_lookup_web_destination_live_preserves_arrays_and_normalizes_protocol(
    connector_app: App,
    build_live_soar_action_input: Callable[..., dict[str, Any]],
) -> None:
    connector_app.handle(
        json.dumps(
            build_live_soar_action_input(
                action="lookup_web_destination",
                parameters={"destinations": "HTTPS://example.com, 8.8.8.8"},
            )
        )
    )
    result = connector_app.actions_manager.get_action_results()[-1]
    assert result.get_status() is True, result.get_message()
    rows = result.get_data()
    assert {row["destination"] for row in rows} == {"example.com", "8.8.8.8"}
    assert all(isinstance(row["blocklisted"], bool) for row in rows)
    assert all(isinstance(row["urlClassifications"], list) for row in rows)
    assert all(
        isinstance(row["urlClassificationsWithSecurityAlert"], list) for row in rows
    )
