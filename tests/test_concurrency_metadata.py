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
from src.app import create_zscaler_soar_connector_app


ASSET_MUTATION_ACTIONS = {
    "add_category_ip",
    "add_category_url",
    "add_group_user",
    "allow_ip",
    "allow_url",
    "block_ip",
    "block_url",
    "create_destination_group",
    "delete_destination_group",
    "edit_destination_group",
    "remove_category_ip",
    "remove_category_url",
    "remove_group_user",
    "unallow_ip",
    "unallow_url",
    "unblock_ip",
    "unblock_url",
    "update_user",
}


def test_shared_asset_mutations_are_exclusive() -> None:
    app = create_zscaler_soar_connector_app()
    action_metadata = {
        action.identifier: action.model_dump()
        for action in app.actions_manager.get_actions_meta_list()
    }

    for identifier, metadata in action_metadata.items():
        if identifier in ASSET_MUTATION_ACTIONS:
            assert metadata["lock"] == {
                "enabled": True,
                "concurrency": False,
            }
        else:
            assert "lock" not in metadata
