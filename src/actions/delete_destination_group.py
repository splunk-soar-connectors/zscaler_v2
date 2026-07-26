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


class DeleteDestinationGroupParams(Params):
    ip_group_ids: str = Param(
        description="A comma-separated list of unique identifiers for the IP destination groups",
        primary=True,
    )


class DeleteDestinationGroupOutput(PermissiveActionOutput):
    ip_group_id: str


class DeleteDestinationGroupSummary(ActionOutput):
    message: str = OutputField(example_values=["Destination groups deleted"])


def delete_destination_group(
    params: DeleteDestinationGroupParams, soar: SOARClient, asset: Asset
) -> list[DeleteDestinationGroupOutput]:
    group_ids = [
        item.strip() for item in params.ip_group_ids.split(",") if item.strip()
    ]

    try:
        rows: list[DeleteDestinationGroupOutput] = []
        with get_client(asset) as client:
            for group_id in group_ids:
                _deleted, _response, error = (
                    client.zia.cloud_firewall.delete_ip_destination_group(int(group_id))
                )
                if error is not None:
                    raise RuntimeError(f"Zscaler API error: {error}")
                rows.append(DeleteDestinationGroupOutput(**{"ip_group_id": group_id}))

            activation, _response, activation_error = client.zia.activate.activate()
            if activation_error is not None:
                raise RuntimeError(f"Zscaler API error: {activation_error}")
            if activation is None:
                raise RuntimeError("Zscaler API returned no activation response")
    except Exception as exc:
        logger.exception("Delete destination group failed")
        message = f"Delete destination group failed: {exc}"
        soar.set_message(message)
        raise ActionFailure(message) from exc

    soar.set_summary(
        DeleteDestinationGroupSummary(message="Destination groups deleted")
    )
    return rows
