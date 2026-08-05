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


EXPECTED_TABLE_COLUMNS = {
    "get_admin_users": [
        "Admin ID",
        "Name",
        "Login",
        "Email",
        "Role",
        "Disabled",
    ],
    "get_category_details": [
        "Category ID",
        "Configured Name",
        "Description",
        "Custom",
        "Editable",
        "Keywords",
        "URLs",
    ],
    "get_denylist": ["URL"],
    "get_departments": ["Department Id", "Department Name", "Non-editable"],
    "get_groups": ["Group ID", "Group Name", "Comments", "Non-editable"],
    "get_users": ["User ID", "User Name", "Email", "Department", "Disabled"],
    "list_destination_group": [
        "Group ID",
        "Group Name",
        "Type",
        "Addresses",
        "Countries",
        "Description",
        "IP Categories",
        "Non-editable",
    ],
    "list_url_categories": [
        "Category ID",
        "Configured Name",
        "Description",
        "Custom",
        "Editable",
    ],
    "lookup_web_destination": [
        "Destination",
        "Classifications",
        "Security Alerts",
        "Blocklisted",
    ],
}


def test_selected_table_columns_match_renderer_contract() -> None:
    app = create_zscaler_soar_connector_app()
    action_meta = {
        action.identifier: action
        for action in app.actions_manager.get_actions_meta_list()
    }

    for identifier, expected_columns in EXPECTED_TABLE_COLUMNS.items():
        serialized = action_meta[identifier].model_dump()
        assert serialized["render"] == {"type": "table"}

        selected_fields = [
            field for field in serialized["output"] if "column_name" in field
        ]
        selected_fields.sort(key=lambda field: field["column_order"])

        assert [field["column_name"] for field in selected_fields] == expected_columns
        assert [field["column_order"] for field in selected_fields] == list(
            range(len(expected_columns))
        )
