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


class GetCategoryDetailsParams(Params):
    category_ids: str = Param(
        description="Comma-separated list of category IDs to query", primary=True
    )


class ScopesOutput(ActionOutput):
    Type: str = OutputField(example_values=["test ORGANIZATION"])


class GetCategoryDetailsOutput(PermissiveActionOutput):
    configuredName: str | None = OutputField(example_values=["test Test-Caution"])
    customCategory: bool | None = None
    keywords: list[str] | None = None
    urls: list[str] | None = None
    customIpRangesCount: float | None = OutputField(example_values=[0])
    customUrlsCount: float | None = OutputField(example_values=[0])
    dbCategorizedUrls: list[str] | None = OutputField(example_values=["test 6.5.3.2.4"])
    keywordsRetainingParentCategory: list[str] | None = None
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


class GetCategoryDetailsSummary(ActionOutput):
    message: str = OutputField(example_values=["Category details recieved"])
    total_categories: int = OutputField(example_values=[97])


def get_category_details(
    params: GetCategoryDetailsParams, soar: SOARClient, asset: Asset
) -> list[GetCategoryDetailsOutput]:
    category_ids = [
        category_id.strip()
        for category_id in params.category_ids.split(",")
        if category_id.strip()
    ]

    try:
        rows: list[GetCategoryDetailsOutput] = []
        with get_client(asset) as client:
            for category_id in category_ids:
                category, response, error = client.zia.url_categories.get_category(
                    category_id
                )
                if error is not None:
                    raise RuntimeError(f"Zscaler API error: {error}")
                if category is None or response is None:
                    raise RuntimeError(
                        f"Zscaler API returned no details for category {category_id}"
                    )

                raw_category = response.get_body()
                if not isinstance(raw_category, dict):
                    raise RuntimeError(
                        f"Zscaler API returned invalid details for category {category_id}"
                    )
                rows.append(GetCategoryDetailsOutput(**raw_category))
    except Exception as exc:
        logger.exception("Get category details failed")
        message = f"Get category details failed: {exc}"
        soar.set_message(message)
        raise ActionFailure(message) from exc

    message = "Category details recieved"
    soar.set_summary(
        GetCategoryDetailsSummary(
            message=message,
            total_categories=len(rows),
        )
    )
    soar.set_message(message)
    return rows
