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
from soar_sdk.params import Param, Params

from ..asset import Asset


class ListDestinationGroupParams(Params):
    ip_group_ids: str | None = Param(
        description="A comma-separated list of unique identifiers for the IP destination groups",
        primary=True,
    )
    exclude_type: str | None = Param(
        description="The IP group type to be excluded from the results", primary=True
    )
    category_type: str | None = Param(
        description="Comma seperated list of IP group types to be filtered from results. This argument is only supported when the 'lite' argument is set to True"
    )
    limit: float | None = Param(
        description="Limit of the results to be retrieved", default=50
    )
    lite: bool | None = Param(
        description="Whether to retrieve only limited information of IP destination groups. Includes ID, name and type of the IP destination groups",
        default=False,
    )


class ListDestinationGroupOutput(ActionOutput):
    id: float
    name: str
    type: str = OutputField(
        example_values=["DSTN_IP", "DSTN_FQDN", "DSTN_DOMAIN", "DSTN_OTHER"]
    )
    addresses: str = OutputField(example_values=["192.168.1.1"])
    countries: str
    description: str
    ipCategories: str = OutputField(example_values=["TRADING_BROKARAGE_INSURANCE"])
    isNonEditable: bool
    creatorContext: str


def list_destination_group(
    params: ListDestinationGroupParams, soar: SOARClient, asset: Asset
) -> ListDestinationGroupOutput:
    raise NotImplementedError()
