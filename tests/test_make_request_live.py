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


def test_make_request_live_gets_zia_activation_status(
    connector_app: App,
    build_live_soar_action_input: Callable[..., dict[str, Any]],
) -> None:
    input_data = build_live_soar_action_input(
        action="make_request",
        parameters={
            "http_method": "GET",
            "endpoint": "/zia/api/v1/status",
            "timeout": 60,
            "verify_ssl": True,
        },
    )

    connector_app.handle(json.dumps(input_data))

    result = connector_app.actions_manager.get_action_results()[-1]
    assert result.get_status() is True, result.get_message()
    data = result.get_data()
    assert len(data) == 1
    assert data[0]["status_code"] == 200
    response_body = json.loads(data[0]["response_body"])
    assert response_body["status"] in {"ACTIVE", "PENDING", "IN_PROGRESS"}
