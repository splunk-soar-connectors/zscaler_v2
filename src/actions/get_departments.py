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
from pydantic import Field
from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput, OutputField
from soar_sdk.exceptions import ActionFailure
from soar_sdk.logging import getLogger
from soar_sdk.params import Param, Params

from ..asset import Asset
from ..zscaler_client import get_client

logger = getLogger()


class GetDepartmentsParams(Params):
    name: str | None = Param(description="Filter by department name", primary=True)
    page: float | None = Param(description="Specifies the page offset", primary=True)
    pageSize: float | None = Param(
        description="Specifies the page size", primary=True, default=100
    )


class GetDepartmentsOutput(ActionOutput):
    id: int = OutputField(column_name="Department Id")
    name: str = OutputField(column_name="Department Name")
    isNonEditable: bool = Field(json_schema_extra={"column_name": "Is editable"})


class GetDepartmentsSummary(ActionOutput):
    message: str = OutputField(example_values=["Departments Retrieved"])
    total_deparments: int = OutputField(example_values=[97])


def get_departments(
    params: GetDepartmentsParams, soar: SOARClient, asset: Asset
) -> list[GetDepartmentsOutput]:
    page = params.page if params.page is not None else 1
    page_size = params.pageSize if params.pageSize is not None else 100
    if isinstance(page, float) and page.is_integer():
        page = int(page)
    if isinstance(page_size, float) and page_size.is_integer():
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
            rows.append(GetDepartmentsOutput.model_construct(**department))
    except Exception as exc:
        logger.exception("Get departments failed")
        message = f"Get departments failed: {exc}"
        soar.set_message(message)
        raise ActionFailure(message) from exc

    soar.set_summary(
        GetDepartmentsSummary(
            message="Departments retrieved",
            total_deparments=len(rows),
        )
    )
    return rows
