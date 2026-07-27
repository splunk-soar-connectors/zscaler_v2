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

from src.actions.get_category_details import GetCategoryDetailsParams


def test_get_category_details_requires_category_ids() -> None:
    assert GetCategoryDetailsParams.model_fields["category_ids"].is_required()


def test_get_category_details_live_returns_oneapi_lists(
    connector_app: App,
    build_soar_action_input: Callable[..., dict[str, Any]],
) -> None:
    list_input = build_soar_action_input(
        action="list_url_categories",
        parameters={"get_ids_and_names_only": True},
    )
    connector_app.handle(json.dumps(list_input))
    list_result = connector_app.actions_manager.get_action_results()[-1]
    assert list_result.get_status() is True, list_result.get_message()
    category_ids = [row["id"] for row in list_result.get_data()[:2]]
    assert category_ids

    details_input = build_soar_action_input(
        action="get_category_details",
        parameters={"category_ids": ", ".join(category_ids)},
    )
    connector_app.handle(json.dumps(details_input))

    result = connector_app.actions_manager.get_action_results()[-1]
    assert result.get_status() is True, result.get_message()
    assert result.get_message() == "Category details received"

    rows = result.get_data()
    assert [row["id"] for row in rows] == category_ids
    for field in ("keywords", "urls", "dbCategorizedUrls"):
        assert all(field not in row or isinstance(row[field], list) for row in rows)
    assert result.get_summary() == {
        "total_categories": len(rows),
    }
