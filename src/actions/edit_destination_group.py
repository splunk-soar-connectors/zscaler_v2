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


class EditDestinationGroupParams(Params):
    ip_group_id: float = Param(
        description="The unique identifier for the IP destination group", primary=True
    )
    name: str | None = Param(description="Destination IP group name", primary=True)
    addresses: str | None = Param(
        description="Comma seperated string of destination IP addresses, FQDNs, or wildcard FQDNs added to the group"
    )
    description: str | None = Param(
        description="Additional information about the destination IP group."
    )
    ip_categories: str | None = Param(
        description="Destination IP address URL categories"
    )
    countries: str | None = Param(
        description="Destination IP address countries. You can identify destinations based on the location of a server."
    )
    is_non_editable: bool | None = Param(
        description="If set to true, the destination IP address group is non-editable. This field is applicable only to predefined IP address groups, which cannot be modified",
        default=False,
    )


class EditDestinationGroupOutput(ActionOutput):
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


def edit_destination_group(
    params: EditDestinationGroupParams, soar: SOARClient, asset: Asset
) -> EditDestinationGroupOutput:
    raise NotImplementedError()
