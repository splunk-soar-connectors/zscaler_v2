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


class CreateDestinationGroupParams(Params):
    name: str = Param(description="Destination IP group name", primary=True)
    type: str = Param(
        description="Destination IP group type (i.e., the group can contain destination IP addresses, countries, URL categories or FQDNs)",
        primary=True,
    )
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


class CreateDestinationGroupOutput(ActionOutput):
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


def create_destination_group(
    params: CreateDestinationGroupParams, soar: SOARClient, asset: Asset
) -> CreateDestinationGroupOutput:
    raise NotImplementedError()
