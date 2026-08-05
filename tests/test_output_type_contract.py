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


def _outputs_by_action() -> dict[str, dict[str, dict[str, object]]]:
    app = create_zscaler_soar_connector_app()
    return {
        action.identifier: {
            output["data_path"]: output for output in action.model_dump()["output"]
        }
        for action in app.actions_manager.get_actions_meta_list()
    }


def test_collection_outputs_use_wildcard_datapaths() -> None:
    outputs = _outputs_by_action()

    expected_collection_paths = {
        "allow_web_destination": {
            "action_result.data.*.whitelistUrls.*",
            "action_result.summary.ignored.*",
            "action_result.summary.updated.*",
        },
        "block_web_destination": {
            "action_result.summary.ignored.*",
            "action_result.summary.updated.*",
        },
        "get_category_details": {
            "action_result.data.*.keywords.*",
            "action_result.data.*.urls.*",
        },
        "list_destination_group": {
            "action_result.data.*.addresses.*",
            "action_result.data.*.countries.*",
            "action_result.data.*.ipCategories.*",
        },
        "lookup_web_destination": {
            "action_result.data.*.urlClassifications.*",
            "action_result.data.*.urlClassificationsWithSecurityAlert.*",
        },
    }

    for action, expected_paths in expected_collection_paths.items():
        assert expected_paths <= outputs[action].keys()


def test_echoed_parameters_keep_numeric_and_boolean_types() -> None:
    outputs = _outputs_by_action()

    assert (
        outputs["get_departments"]["action_result.parameter.page"]["data_type"]
        == "numeric"
    )
    assert (
        outputs["get_departments"]["action_result.parameter.page_size"]["data_type"]
        == "numeric"
    )
    assert (
        outputs["list_url_categories"][
            "action_result.parameter.get_ids_and_names_only"
        ]["data_type"]
        == "boolean"
    )
