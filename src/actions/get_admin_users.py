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
from typing import Any

from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput, OutputField, PermissiveActionOutput
from soar_sdk.exceptions import ActionFailure
from soar_sdk.logging import getLogger
from soar_sdk.params import Param, Params

from ..asset import Asset
from ..zscaler_client import get_client

logger = getLogger()

_MAX_PAGE_SIZE = 1000


class GetAdminUsersParams(Params):
    limit: float | None = Param(
        description="Maximum number of records to fetch", default=1000
    )


class AdminscopescopeentitiesOutput(ActionOutput):
    id: float = OutputField(example_values=[4460340])
    name: str = OutputField(example_values=["test Example App"])


class AdminscopescopegroupmemberentitiesOutput(ActionOutput):
    id: float = OutputField(example_values=[8035054])


class ExtensionsOutput(ActionOutput):
    adminRank: str
    roleType: str


class RoleOutput(ActionOutput):
    extensions: ExtensionsOutput
    id: float
    isNameL10nTag: bool = OutputField(example_values=[True])
    name: str = OutputField(example_values=["test Super Admin"])


class GetAdminUsersOutput(PermissiveActionOutput):
    adminScopeScopeEntities: list[AdminscopescopeentitiesOutput]
    adminScopeType: str
    adminScopescopeGroupMemberEntities: list[AdminscopescopegroupmemberentitiesOutput]
    comments: str = OutputField(example_values=["test This is test user"])
    disabled: bool = OutputField(example_values=[True])
    email: str = OutputField(
        cef_types=["email"], example_values=["test first.last@emaildomain.com"]
    )
    id: float = OutputField(cef_types=["zscaler user id"], example_values=[889814])
    isDefaultAdmin: bool = OutputField(example_values=[True])
    isDeprecatedDefaultAdmin: bool = OutputField(example_values=[True])
    isExecMobileAppEnabled: bool = OutputField(example_values=[True])
    isNonEditable: bool
    isPasswordLoginAllowed: bool
    isProductUpdateCommEnabled: bool = OutputField(example_values=[True])
    isSecurityReportCommEnabled: bool = OutputField(example_values=[True])
    isServiceUpdateCommEnabled: bool = OutputField(example_values=[True])
    loginName: str = OutputField(example_values=["test first.last@domain.com"])
    name: str = OutputField(
        example_values=[
            "test new_test_long_email_id_new_test_long_email_id_new_test_long_email_id_new_test_long_email"
        ]
    )
    pwdLastModifiedTime: float
    role: RoleOutput
    userName: str = OutputField(example_values=["test Last, First"])


class GetAdminUsersSummary(ActionOutput):
    total_admin_users: int = OutputField(example_values=[10])


def get_admin_users(
    params: GetAdminUsersParams, soar: SOARClient, asset: Asset
) -> list[GetAdminUsersOutput]:
    if (
        params.limit is None
        or not float(params.limit).is_integer()
        or params.limit <= 0
    ):
        message = "Limit must be a positive integer."
        soar.set_message(message)
        raise ActionFailure(message)
    limit = int(params.limit)

    try:
        raw_admins: list[dict[str, Any]] = []
        page = 1
        remaining = limit
        with get_client(asset) as client:
            while remaining > 0:
                _admins, response, error = client.zia.admin_users.list_admin_users(
                    {
                        "page": page,
                        "page_size": min(remaining, _MAX_PAGE_SIZE),
                    }
                )
                if error is not None:
                    raise RuntimeError(f"Zscaler API error: {error}")
                if response is None:
                    raise RuntimeError("Zscaler API returned no admin users response")

                page_admins = response.get_results()
                if not isinstance(page_admins, list):
                    raise RuntimeError(
                        "Zscaler API returned an invalid admin users list"
                    )
                if not page_admins:
                    break
                for admin in page_admins:
                    if not isinstance(admin, dict):
                        raise RuntimeError(
                            "Zscaler API returned an invalid admin user record"
                        )
                    raw_admins.append(admin)
                remaining -= len(page_admins)
                page += 1

        rows = [GetAdminUsersOutput(**admin) for admin in raw_admins[:limit]]
    except Exception as exc:
        logger.exception("Get admin users failed")
        message = f"Get admin users failed: {exc}"
        soar.set_message(message)
        raise ActionFailure(message) from exc

    soar.set_summary(GetAdminUsersSummary(total_admin_users=len(rows)))
    return rows
