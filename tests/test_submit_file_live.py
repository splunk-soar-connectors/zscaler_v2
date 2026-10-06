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
import os
from collections.abc import Callable
from pathlib import Path
from typing import Any

from soar_sdk.app import App

from tests.conftest import SANDBOX_TEST_FILE_MD5


def test_submit_file_live_submits_connector_fixture(
    connector_app: App,
    build_live_soar_action_input: Callable[..., dict[str, Any]],
    sandbox_live_asset_config: dict[str, str],
    sandbox_test_file: Path,
) -> None:
    del sandbox_live_asset_config
    vault_id = connector_app.soar_client.vault.add_attachment(
        container_id=int(os.environ.get("SOAR_CONTAINER_ID", "456")),
        file_location=str(sandbox_test_file),
        file_name=sandbox_test_file.name,
    )
    connector_app.handle(
        json.dumps(
            build_live_soar_action_input(
                action="submit_file",
                parameters={"vault_id": vault_id, "force": False},
            )
        )
    )

    result = connector_app.actions_manager.get_action_results()[-1]
    assert result.get_status() is True, result.get_message()
    rows = result.get_data()
    assert len(rows) == 1
    assert rows[0]["code"] == 200
    assert rows[0]["md5"].casefold() == SANDBOX_TEST_FILE_MD5
    assert {"code", "md5", "message"} <= rows[0].keys()
