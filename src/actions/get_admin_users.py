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


class GetAdminUsersOutput(ActionOutput):
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


def get_admin_users(
    params: GetAdminUsersParams, soar: SOARClient, asset: Asset
) -> GetAdminUsersOutput:
    raise NotImplementedError()
