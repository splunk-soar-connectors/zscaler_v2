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
    deleted_destination_groups: int = OutputField(example_values=[1])


def delete_destination_group(
    params: DeleteDestinationGroupParams, soar: SOARClient, asset: Asset
) -> list[DeleteDestinationGroupOutput]:
    group_ids = [
        item.strip() for item in params.ip_group_ids.split(",") if item.strip()
    ]
    if not group_ids:
        message = "Delete destination group failed: provide at least one ip_group_id"
        soar.set_message(message)
        raise ActionFailure(message)

    invalid_group_ids: list[str] = []
    numeric_group_ids: list[int] = []
    for group_id in group_ids:
        try:
            numeric_group_id = int(group_id)
        except ValueError:
            invalid_group_ids.append(group_id)
            continue
        if numeric_group_id <= 0 or str(numeric_group_id) != group_id:
            invalid_group_ids.append(group_id)
            continue
        numeric_group_ids.append(numeric_group_id)

    if invalid_group_ids:
        message = (
            "Delete destination group failed: every ip_group_id must be a positive "
            f"integer; invalid values: {', '.join(invalid_group_ids)}"
        )
        soar.set_message(message)
        raise ActionFailure(message)

    try:
        rows: list[DeleteDestinationGroupOutput] = []
        failed_group_id: str | None = None
        delete_error: object | None = None
        with get_client(asset) as client:
            for group_id, numeric_group_id in zip(
                group_ids, numeric_group_ids, strict=True
            ):
                _deleted, _response, error = (
                    client.zia.cloud_firewall.delete_ip_destination_group(
                        numeric_group_id
                    )
                )
                if error is not None:
                    failed_group_id = group_id
                    delete_error = error
                    break
                rows.append(DeleteDestinationGroupOutput(**{"ip_group_id": group_id}))

            if rows:
                activation, _response, activation_error = client.zia.activate.activate()
                if activation_error is not None or activation is None:
                    detail = (
                        activation_error or "Zscaler API returned no activation data"
                    )
                    deleted = ", ".join(row.ip_group_id for row in rows)
                    failed_deletion = (
                        f" Deletion also failed for ID {failed_group_id}: "
                        f"{delete_error}."
                        if failed_group_id is not None
                        else ""
                    )
                    raise RuntimeError(
                        "The destination groups were deleted but could not be "
                        "activated and are not yet enforced. "
                        f"Deleted IDs: {deleted}.{failed_deletion} {detail}"
                    )

            if failed_group_id is not None:
                deleted = ", ".join(row.ip_group_id for row in rows) or "none"
                raise RuntimeError(
                    f"Zscaler API error deleting destination group "
                    f"{failed_group_id}: {delete_error}. Deleted and activated IDs "
                    f"before the failure: {deleted}"
                )
    except Exception as exc:
        logger.exception("Delete destination group failed")
        message = f"Delete destination group failed: {exc}"
        soar.set_message(message)
        raise ActionFailure(message) from exc

    soar.set_summary(
        DeleteDestinationGroupSummary(deleted_destination_groups=len(rows))
    )
    soar.set_message("Destination groups deleted")
    return rows
