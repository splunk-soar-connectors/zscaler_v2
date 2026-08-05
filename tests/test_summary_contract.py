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


POLICY_CHANGE_SUMMARY = {
    "action_result.summary.ignored.*",
    "action_result.summary.updated.*",
}

EXPECTED_ACTION_SUMMARIES = {
    "allow_web_destination": POLICY_CHANGE_SUMMARY,
    "block_web_destination": POLICY_CHANGE_SUMMARY,
    "delete_destination_group": {"action_result.summary.deleted_destination_groups"},
    "get_admin_users": {"action_result.summary.total_admin_users"},
    "get_allowlist": {"action_result.summary.total_allowlist_items"},
    "get_category_details": {"action_result.summary.total_categories"},
    "get_denylist": {"action_result.summary.total_denylist_items"},
    "get_departments": {"action_result.summary.total_departments"},
    "get_groups": {"action_result.summary.total_groups"},
    "get_users": {"action_result.summary.total_users"},
    "list_destination_group": {"action_result.summary.total_destination_groups"},
    "list_url_categories": {"action_result.summary.total_url_categories"},
    "remove_allowed_web_destination": POLICY_CHANGE_SUMMARY,
    "unblock_ip": POLICY_CHANGE_SUMMARY,
    "unblock_url": POLICY_CHANGE_SUMMARY,
}


def test_action_summaries_contain_only_meaningful_typed_fields() -> None:
    app = create_zscaler_soar_connector_app()

    for action in app.actions_manager.get_actions_meta_list():
        serialized = action.model_dump()
        summary_paths = {
            output["data_path"]
            for output in serialized["output"]
            if output["data_path"].startswith("action_result.summary")
        }

        assert summary_paths == EXPECTED_ACTION_SUMMARIES.get(action.identifier, set())
