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
from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput, OutputField
from soar_sdk.exceptions import ActionFailure
from soar_sdk.logging import getLogger
from soar_sdk.params import Param, Params

from ..asset import Asset
from ..zscaler_client import get_client

logger = getLogger()

_MAX_PAGE_SIZE = 1000


class GetDepartmentsParams(Params):
    name: str | None = Param(description="Filter by department name", primary=True)
    page: float | None = Param(
        description="Page number, starting at 1", primary=True, default=1
    )
    page_size: float | None = Param(
        description="Number of departments per page, from 1 to 1000",
        primary=True,
        default=100,
    )


class GetDepartmentsOutput(ActionOutput):
    id: int = OutputField(column_name="Department Id")
    name: str = OutputField(column_name="Department Name")
    isNonEditable: bool | None = OutputField(
        column_name="Non-editable",
    )


class GetDepartmentsSummary(ActionOutput):
    total_departments: int = OutputField(example_values=[97])


def get_departments(
    params: GetDepartmentsParams, soar: SOARClient, asset: Asset
) -> list[GetDepartmentsOutput]:
    page = params.page if params.page is not None else 1
    page_size = params.page_size if params.page_size is not None else 100
    if not float(page).is_integer() or page < 1:
        message = "Page must be a positive integer."
        soar.set_message(message)
        raise ActionFailure(message)
    if not float(page_size).is_integer() or page_size < 1 or page_size > _MAX_PAGE_SIZE:
        message = f"Page size must be an integer from 1 to {_MAX_PAGE_SIZE}."
        soar.set_message(message)
        raise ActionFailure(message)

    page = int(page)
    page_size = int(page_size)

    query_params: dict[str, str | int | float | bool] = {
        "page": page,
        "page_size": page_size,
    }
    if params.name:
        query_params["search"] = params.name
        query_params["limit_search"] = True

    try:
        with get_client(asset) as client:
            _departments, response, error = client.zia.user_management.list_departments(
                query_params
            )
            if error is not None:
                raise RuntimeError(f"Zscaler API error: {error}")
            if response is None:
                raise RuntimeError("Zscaler API returned no departments response")

            # zscaler-sdk-python 1.9.38 deserializes this endpoint into
            # UserManagement and drops isNonEditable. The SDK response retains the
            # original department records.
            raw_departments = response.get_results()
            if not isinstance(raw_departments, list):
                raise RuntimeError("Zscaler API returned an invalid departments list")

        rows: list[GetDepartmentsOutput] = []
        for department in raw_departments:
            if not isinstance(department, dict):
                raise RuntimeError("Zscaler API returned an invalid department record")
            if not isinstance(department.get("id"), int) or not isinstance(
                department.get("name"), str
            ):
                raise RuntimeError("Zscaler API returned an invalid department record")
            if "isNonEditable" in department and not isinstance(
                department["isNonEditable"], bool
            ):
                raise RuntimeError("Zscaler API returned an invalid department record")
            rows.append(GetDepartmentsOutput(**department))
    except Exception as exc:
        logger.exception("Get departments failed")
        message = f"Get departments failed: {exc}"
        soar.set_message(message)
        raise ActionFailure(message) from exc

    soar.set_summary(GetDepartmentsSummary(total_departments=len(rows)))
    soar.set_message("Departments retrieved")
    return rows
