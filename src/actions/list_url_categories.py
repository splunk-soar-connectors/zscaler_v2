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
from soar_sdk.action_results import ActionOutput, OutputField, PermissiveActionOutput
from soar_sdk.exceptions import ActionFailure
from soar_sdk.logging import getLogger
from soar_sdk.params import Param, Params

from ..asset import Asset
from ..zscaler_client import get_client

logger = getLogger()


class ListUrlCategoriesParams(Params):
    get_ids_and_names_only: bool | None = Param(
        description="Whether to retrieve only a list containing URL category IDs and names. Even if displayURL is set to true, URLs will not be returned",
        primary=True,
        default=False,
    )


class ScopesOutput(ActionOutput):
    Type: str = OutputField(example_values=["test ORGANIZATION"])


class ListUrlCategoriesOutput(PermissiveActionOutput):
    configuredName: str | None = OutputField(example_values=["test Test-Caution"])
    customCategory: bool | None = None
    customIpRangesCount: float | None = OutputField(example_values=[0])
    customUrlsCount: float | None = OutputField(example_values=[0])
    dbCategorizedUrls: list[str] | None = OutputField(example_values=["test 6.5.3.2.4"])
    description: str | None = OutputField(
        example_values=["test OTHER_RESTRICTED_WEBSITE_DESC"]
    )
    editable: bool | None = None
    id: str | None = OutputField(
        cef_types=["zscaler url category"],
        example_values=["test OTHER_RESTRICTED_WEBSITE"],
    )
    ipRangesRetainingParentCategoryCount: float | None = OutputField(example_values=[0])
    scopes: list[ScopesOutput] | None = None
    type: str | None = OutputField(example_values=["test URL_CATEGORY"])
    urlsRetainingParentCategoryCount: float | None = OutputField(example_values=[0])
    val: float | None = OutputField(example_values=[1])


class ListUrlCategoriesSummary(ActionOutput):
    total_url_categories: int = OutputField(example_values=[10])


def list_url_categories(
    params: ListUrlCategoriesParams, soar: SOARClient, asset: Asset
) -> list[ListUrlCategoriesOutput]:
    try:
        with get_client(asset) as client:
            categories, response, error = client.zia.url_categories.list_categories()
            if error is not None:
                raise RuntimeError(f"Zscaler API error: {error}")
            if not isinstance(categories, list) or response is None:
                raise RuntimeError("Zscaler API returned an invalid category list")

            raw_categories = response.get_results()
            if not isinstance(raw_categories, list):
                raise RuntimeError("Zscaler API returned an invalid category list")

        rows: list[ListUrlCategoriesOutput] = []
        for category in raw_categories:
            if not isinstance(category, dict):
                raise RuntimeError("Zscaler API returned an invalid category record")
            row_data = category
            if params.get_ids_and_names_only:
                row_data = {
                    key: category[key]
                    for key in ("id", "configuredName")
                    if key in category
                }
            rows.append(ListUrlCategoriesOutput(**row_data))
    except Exception as exc:
        logger.exception("List URL categories failed")
        message = f"List URL categories failed: {exc}"
        soar.set_message(message)
        raise ActionFailure(message) from exc

    soar.set_summary(ListUrlCategoriesSummary(total_url_categories=len(rows)))
    return rows
