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
from soar_sdk.app import App
from soar_sdk.params import Param, Params
from soar_sdk.action_results import ActionOutput, OutputField
from soar_sdk.asset import BaseAsset, AssetField
from soar_sdk.logging import getLogger

logger = getLogger()


class Asset(BaseAsset):
    base_url: str = AssetField(
        description="Base URL (e.g. https://admin.zscaler_instance.net)"
    )
    api_key: str = AssetField(description="API Key")
    username: str = AssetField(description="Username")
    password: str = AssetField(description="Password")
    sandbox_base_url: str | None = AssetField(description="Sandbox Base URL")
    sandbox_api_token: str | None = AssetField(description="Sandbox API Token")


app = App(
    name="zscaler_v2",
    app_type="network security",
    logo="logo_zscaler.svg",
    logo_dark="logo_zscaler_dark.svg",
    product_vendor="Zscaler",
    product_name="Zscaler v2",
    publisher="Splunk",
    appid="6f172977-769c-4f3f-b521-ded635067483",
    fips_compliant=True,
    asset_cls=Asset,
)


@app.test_connectivity()
def test_connectivity(soar: SOARClient, asset: Asset) -> None:
    raise NotImplementedError()


class GetReportParams(Params):
    file_hash: str = Param(
        description="The md5 file hash", primary=True, cef_types=["md5"]
    )


class ClassificationOutput(ActionOutput):
    Category: str = OutputField(example_values=["test BENIGN"])
    DetectedMalware: str
    Score: float = OutputField(example_values=[10])
    Type: str = OutputField(example_values=["test BENIGN"])


class FilepropertiesOutput(ActionOutput):
    DigitalCerificate: str
    FileSize: float = OutputField(example_values=[350084])
    FileType: str = OutputField(example_values=["test EXE"])
    Issuer: str
    MD5: str = OutputField(
        cef_types=["md5"], example_values=["test 1043ca3fc2e83f0c6f100e46d2ea16be"]
    )
    RootCA: str
    SHA1: str = OutputField(
        cef_types=["sha1"],
        example_values=["test efbd493b33543341d43df6db4c92de2473cf49f3"],
    )
    SSDeep: str = OutputField(
        example_values=[
            "test 6144:IFkS+8dpN9EtEnROO4T0LbTbHiXuFW0XPBGunX9v62HCTAA1PSahJj3zDbSJ8:CkMy4TGWXuFR5JAxS6Lnbu8"
        ]
    )
    Sha256: str = OutputField(
        cef_types=["sha256"],
        example_values=[
            "test 0e7fd4dde827a7f0bda82bbfbce4b92a551d0cd296f72e936b8968310d2181cd"
        ],
    )


class OriginOutput(ActionOutput):
    Country: str = OutputField(example_values=["test United States"])
    Language: str = OutputField(example_values=["test English"])
    Risk: str = OutputField(example_values=["test LOW"])


class SummaryOutput(ActionOutput):
    Category: str = OutputField(example_values=["test EXECS"])
    Duration: float = OutputField(example_values=[524114])
    FileType: str = OutputField(example_values=["test EXE"])
    StartTime: float = OutputField(example_values=[1520334357])
    Status: str = OutputField(example_values=["test COMPLETED"])


class SystemsummaryOutput(ActionOutput):
    Risk: str = OutputField(example_values=["test LOW"])
    Signature: str = OutputField(
        example_values=["test Binary contains paths to development resources"]
    )
    SignatureSources: str = OutputField(example_values=["test no activity detected"])


class FullDetailsOutput(ActionOutput):
    Classification: ClassificationOutput
    FileProperties: FilepropertiesOutput
    Origin: OriginOutput
    Summary: SummaryOutput
    SystemSummary: list[SystemsummaryOutput]


class GetReportOutput(ActionOutput):
    Full_Details: FullDetailsOutput


@app.action(
    description="Fetch sandbox report for provided md5 file hash",
    action_type="investigate",
)
def get_report(
    params: GetReportParams, soar: SOARClient, asset: Asset
) -> GetReportOutput:
    raise NotImplementedError()


class ListUrlCategoriesParams(Params):
    get_ids_and_names_only: bool | None = Param(
        description="Whether to retrieve only a list containing URL category IDs and names. Even if displayURL is set to true, URLs will not be returned",
        primary=True,
        default=False,
    )


class ScopesOutput(ActionOutput):
    Type: str = OutputField(example_values=["test ORGANIZATION"])


class ListUrlCategoriesOutput(ActionOutput):
    configuredName: str = OutputField(example_values=["test Test-Caution"])
    customCategory: bool
    customIpRangesCount: float = OutputField(example_values=[0])
    customUrlsCount: float = OutputField(example_values=[0])
    dbCategorizedUrls: str = OutputField(example_values=["test 6.5.3.2.4"])
    description: str = OutputField(
        example_values=["test OTHER_RESTRICTED_WEBSITE_DESC"]
    )
    editable: bool
    id: str = OutputField(
        cef_types=["zscaler url category"],
        example_values=["test OTHER_RESTRICTED_WEBSITE"],
    )
    ipRangesRetainingParentCategoryCount: float = OutputField(example_values=[0])
    scopes: list[ScopesOutput]
    type: str = OutputField(example_values=["test URL_CATEGORY"])
    urlsRetainingParentCategoryCount: float = OutputField(example_values=[0])
    val: float = OutputField(example_values=[1])


@app.action(description="List all URL categories", action_type="investigate")
def list_url_categories(
    params: ListUrlCategoriesParams, soar: SOARClient, asset: Asset
) -> ListUrlCategoriesOutput:
    raise NotImplementedError()


class BlockIpParams(Params):
    ip: str = Param(
        description="A list of IPs",
        primary=True,
        cef_types=["ip", "ipv6"],
        allow_list=True,
    )
    url_category: str | None = Param(
        description="Add to this category",
        primary=True,
        cef_types=["zscaler url category"],
    )


class BlockIpOutput(ActionOutput):
    configuredName: str = OutputField(example_values=["test Test-Block"])
    customCategory: bool
    dbCategorizedUrls: str
    description: str
    id: str = OutputField(example_values=["test CUSTOM_01"])
    val: float = OutputField(example_values=[128])


@app.action(
    description="Block an IP",
    action_type="contain",
    read_only=False,
    verbose="If a <b>url_category</b> is specified, it will add the IP(s) as a rule to that category. If it is left blank, it will instead add the IP(s) to the global blocklist.",
)
def block_ip(params: BlockIpParams, soar: SOARClient, asset: Asset) -> BlockIpOutput:
    raise NotImplementedError()


class BlockUrlParams(Params):
    url: str = Param(
        description="A list of URLs",
        primary=True,
        cef_types=["url", "url list", "domain"],
        allow_list=True,
    )
    url_category: str | None = Param(
        description="Add to this category",
        primary=True,
        cef_types=["zscaler url category"],
    )


class BlockUrlOutput(ActionOutput):
    configuredName: str = OutputField(example_values=["test Test-Block"])
    customCategory: bool
    customUrlsCount: float = OutputField(example_values=[0])
    dbCategorizedUrls: str
    description: str
    editable: bool
    id: str = OutputField(example_values=["test CUSTOM_01"])
    type: str = OutputField(example_values=["test URL_CATEGORY"])
    urlsRetainingParentCategoryCount: float = OutputField(example_values=[3])
    val: float = OutputField(example_values=[128])


@app.action(
    description="Block a URL",
    action_type="contain",
    read_only=False,
    verbose="If a <b>url_category</b> is specified, it will add the URL(s) as a rule to that category. If it is left blank, it will instead add the URL(s) to the global blocklist.",
)
def block_url(params: BlockUrlParams, soar: SOARClient, asset: Asset) -> BlockUrlOutput:
    raise NotImplementedError()


class UnblockIpParams(Params):
    ip: str = Param(
        description="A list of IPs",
        primary=True,
        cef_types=["ip", "ipv6"],
        allow_list=True,
    )
    url_category: str | None = Param(
        description="Remove from this category",
        primary=True,
        cef_types=["zscaler url category"],
    )


class UnblockIpOutput(ActionOutput):
    configuredName: str = OutputField(example_values=["test Test-Block"])
    customCategory: bool
    dbCategorizedUrls: str
    description: str
    id: str = OutputField(example_values=["test CUSTOM_01"])
    val: float = OutputField(example_values=[128])


@app.action(
    description="Unblock an IP",
    action_type="correct",
    read_only=False,
    verbose="If a <b>url_category</b> is specified, it will remove the IP(s) from that category. If it is left blank, it will instead remove the IP(s) from the global blocklist.",
)
def unblock_ip(
    params: UnblockIpParams, soar: SOARClient, asset: Asset
) -> UnblockIpOutput:
    raise NotImplementedError()


class UnblockUrlParams(Params):
    url: str = Param(
        description="A list of URLs",
        primary=True,
        cef_types=["url", "url list", "domain"],
        allow_list=True,
    )
    url_category: str | None = Param(
        description="Remove from this category",
        primary=True,
        cef_types=["zscaler url category"],
    )


class UnblockUrlOutput(ActionOutput):
    configuredName: str = OutputField(example_values=["test Test-Block"])
    customCategory: bool
    customUrlsCount: float = OutputField(example_values=[0])
    dbCategorizedUrls: str
    description: str
    editable: bool
    id: str = OutputField(example_values=["test CUSTOM_01"])
    type: str = OutputField(example_values=["test URL_CATEGORY"])
    urlsRetainingParentCategoryCount: float = OutputField(example_values=[1])
    val: float = OutputField(example_values=[128])


@app.action(
    description="Unblock a URL",
    action_type="correct",
    read_only=False,
    verbose="If a <b>url_category</b> is specified, it will remove the URL(s) from that category. If it is left blank, it will instead remove the URL(s) from the global blocklist.",
)
def unblock_url(
    params: UnblockUrlParams, soar: SOARClient, asset: Asset
) -> UnblockUrlOutput:
    raise NotImplementedError()


class AllowIpParams(Params):
    ip: str = Param(
        description="A list of IPs",
        primary=True,
        cef_types=["ip", "ipv6"],
        allow_list=True,
    )
    url_category: str | None = Param(
        description="Add to this category",
        primary=True,
        cef_types=["zscaler url category"],
    )


class AllowIpOutput(ActionOutput):
    configuredName: str = OutputField(example_values=["test Test-Allowlist"])
    customCategory: bool
    dbCategorizedUrls: str
    description: str
    id: str = OutputField(example_values=["test CUSTOM_01"])
    val: float = OutputField(example_values=[128])


@app.action(
    description="Add an IP address to the allowlist",
    action_type="contain",
    read_only=False,
    verbose="If a <b>url_category</b> is specified, it will add the IP(s) as a rule to that category. If it is left blank, it will instead add this IP(s) to the global allowlist.",
)
def allow_ip(params: AllowIpParams, soar: SOARClient, asset: Asset) -> AllowIpOutput:
    raise NotImplementedError()


class AllowUrlParams(Params):
    url: str = Param(
        description="A list of URLs",
        primary=True,
        cef_types=["url", "domain", "url list"],
        allow_list=True,
    )
    url_category: str | None = Param(
        description="Add to this category",
        primary=True,
        cef_types=["zscaler url category"],
    )


class AllowUrlOutput(ActionOutput):
    configuredName: str = OutputField(example_values=["test Test-Allowlist"])
    customCategory: bool
    customUrlsCount: float = OutputField(example_values=[0])
    dbCategorizedUrls: str
    description: str
    editable: bool
    id: str = OutputField(example_values=["test CUSTOM_01"])
    type: str = OutputField(example_values=["test URL_CATEGORY"])
    urlsRetainingParentCategoryCount: float = OutputField(example_values=[3])
    val: float = OutputField(example_values=[128])


@app.action(
    description="Add a URL to the allowed list",
    action_type="contain",
    read_only=False,
    verbose="If a <b>url_category</b> is specified, it will add the URL(s) as a rule to that category. If it is left blank, it will instead add the URL(s) to the global allowed list.",
)
def allow_url(params: AllowUrlParams, soar: SOARClient, asset: Asset) -> AllowUrlOutput:
    raise NotImplementedError()


class UnallowIpParams(Params):
    ip: str = Param(
        description="A list of IPs",
        primary=True,
        cef_types=["ip", "ipv6"],
        allow_list=True,
    )
    url_category: str | None = Param(
        description="Remove from this category",
        primary=True,
        cef_types=["zscaler url category"],
    )


class UnallowIpOutput(ActionOutput):
    configuredName: str = OutputField(example_values=["test Test-Allowlist"])
    customCategory: bool
    dbCategorizedUrls: str
    description: str
    id: str = OutputField(example_values=["test CUSTOM_01"])
    val: float = OutputField(example_values=[128])


@app.action(
    description="Remove an IP address from the allowlist",
    action_type="correct",
    read_only=False,
    verbose="If a <b>url_category</b> is specified, it will remove the IP(s) from that category. If it is left blank, it will instead remove the IP(s) from the global allowlist.",
)
def unallow_ip(
    params: UnallowIpParams, soar: SOARClient, asset: Asset
) -> UnallowIpOutput:
    raise NotImplementedError()


class UnallowUrlParams(Params):
    url: str = Param(
        description="A list of URLs",
        primary=True,
        cef_types=["url", "domain", "url list"],
        allow_list=True,
    )
    url_category: str | None = Param(
        description="Remove from this category",
        primary=True,
        cef_types=["zscaler url category"],
    )


class UnallowUrlOutput(ActionOutput):
    configuredName: str = OutputField(example_values=["test Test-Allowlist"])
    customCategory: bool
    dbCategorizedUrls: str
    description: str
    id: str = OutputField(example_values=["test CUSTOM_01"])
    val: float = OutputField(example_values=[128])


@app.action(
    description="Remove a URL from the allowed list",
    action_type="correct",
    read_only=False,
    verbose="If a <b>url_category</b> is specified, it will remove the URL(s) from that category. If it is left blank, it will instead remove the URL(s) from the global allowed list.",
)
def unallow_url(
    params: UnallowUrlParams, soar: SOARClient, asset: Asset
) -> UnallowUrlOutput:
    raise NotImplementedError()


class LookupIpParams(Params):
    ip: str = Param(
        description="A list of IPs",
        primary=True,
        cef_types=["ip", "ipv6"],
        allow_list=True,
    )


class LookupIpOutput(ActionOutput):
    blocklisted: bool
    url: str = OutputField(
        cef_types=["ip", "ipv6"], example_values=["test 208.67.222.222", "test 8.8.8.8"]
    )
    urlClassifications: str = OutputField(example_values=["test WEB_SEARCH"])
    urlClassificationsWithSecurityAlert: str


@app.action(
    description="Lookup the categories related to an IP", action_type="investigate"
)
def lookup_ip(params: LookupIpParams, soar: SOARClient, asset: Asset) -> LookupIpOutput:
    raise NotImplementedError()


class LookupUrlParams(Params):
    url: str = Param(
        description="A list of URLs",
        primary=True,
        cef_types=["url", "domain", "url list"],
        allow_list=True,
    )


class LookupUrlOutput(ActionOutput):
    blocklisted: bool
    url: str = OutputField(
        cef_types=["url", "domain", "url list"], example_values=["test www.test.com"]
    )
    urlClassifications: str = OutputField(
        example_values=["test MISCELLANEOUS_OR_UNKNOWN"]
    )
    urlClassificationsWithSecurityAlert: str


@app.action(
    description="Lookup the categories related to a URL", action_type="investigate"
)
def lookup_url(
    params: LookupUrlParams, soar: SOARClient, asset: Asset
) -> LookupUrlOutput:
    raise NotImplementedError()


class SubmitFileParams(Params):
    vault_id: str = Param(
        description="Vault ID of file to submit",
        primary=True,
        cef_types=["vault id", "sha1"],
    )
    force: bool | None = Param(
        description="Submit file to sandbox even if found malicious during AV scan and a verdict already exists"
    )


class SubmitFileOutput(ActionOutput):
    code: float = OutputField(example_values=[200])
    fileType: str = OutputField(example_values=["test zip"])
    md5: str = OutputField(
        cef_types=["md5"], example_values=["test 6CE6F415D8475545BE5BA114F208B0FF"]
    )
    message: str = OutputField(example_values=["test /submit response OK"])
    sandboxSubmission: str = OutputField(example_values=["test Virus"])
    virusName: str = OutputField(example_values=["test EICAR_Test_File"])
    virusType: str = OutputField(example_values=["test Virus"])


@app.action(
    description="Submit a file to Zscaler Sandbox",
    action_type="generic",
    read_only=False,
    verbose="This action requires a Sandbox Submission API token. By default, files are scanned by Zscaler antivirus (AV) and submitted directly to the sandbox in order to obtain a verdict. However, if a verdict already exists for the file, you can use the 'force' parameter to make the sandbox to reanalyze it. You can submit up to 100 files per day.",
)
def submit_file(
    params: SubmitFileParams, soar: SOARClient, asset: Asset
) -> SubmitFileOutput:
    raise NotImplementedError()


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


@app.action(description="Get a list of admin users", action_type="investigate")
def get_admin_users(
    params: GetAdminUsersParams, soar: SOARClient, asset: Asset
) -> GetAdminUsersOutput:
    raise NotImplementedError()


class GetUsersParams(Params):
    name: str | None = Param(description="User Name/ID")
    dept: str | None = Param(description="User department")
    group: str | None = Param(description="User group")
    limit: float | None = Param(
        description="Maximum number of records to fetch", default=1000
    )


class DepartmentOutput(ActionOutput):
    id: float = OutputField(example_values=[81896690])
    name: str = OutputField(example_values=["test IT"])


class GroupsOutput(ActionOutput):
    id: float = OutputField(cef_types=["zscaler group id"], example_values=[8894813])
    name: str = OutputField(example_values=["test Super Admin"])


class GetUsersOutput(ActionOutput):
    adminUser: bool
    comments: str = OutputField(example_values=["test This is test user"])
    deleted: bool
    department: DepartmentOutput
    disabled: bool = OutputField(example_values=[True])
    email: str = OutputField(
        cef_types=["email"], example_values=["test first.last@domain.com"]
    )
    groups: list[GroupsOutput]
    id: float = OutputField(cef_types=["zscaler user id"], example_values=[889814])
    isNonEditable: bool
    name: str = OutputField(example_values=["test First Last"])


@app.action(
    description="Gets a list of all users and allows user filtering by name, department, or group",
    action_type="investigate",
    verbose="Gets a list of all users and allows user filtering by name, department, or group. The name search parameter performs a partial match. The dept and group parameters perform a 'starts with' match.",
)
def get_users(params: GetUsersParams, soar: SOARClient, asset: Asset) -> GetUsersOutput:
    raise NotImplementedError()


class GetGroupsParams(Params):
    search: str | None = Param(
        description="The search string used to match against a group's name or comments attributes"
    )
    limit: float | None = Param(
        description="Maximum number of records to fetch", default=1000
    )


class GetGroupsOutput(ActionOutput):
    comments: str = OutputField(example_values=["test This is for testing"])
    id: float = OutputField(cef_types=["zscaler group id"], example_values=[8894813])
    isNonEditable: bool = OutputField(example_values=[True])
    name: str = OutputField(example_values=["test Frothly Internet Access"])


@app.action(
    description="Gets a list of groups",
    action_type="investigate",
    verbose="Gets a list of groups. The search parameters find matching values in the name or comments attributes.",
)
def get_groups(
    params: GetGroupsParams, soar: SOARClient, asset: Asset
) -> GetGroupsOutput:
    raise NotImplementedError()


class AddGroupUserParams(Params):
    user_id: float = Param(
        description="ZScaler User ID", primary=True, cef_types=["zscaler user id"]
    )
    group_id: float = Param(
        description="ZScaler Group ID", primary=True, cef_types=["zscaler group id"]
    )


class DepartmentOutput(ActionOutput):
    id: float = OutputField(example_values=[4459551])
    name: str = OutputField(example_values=["test Service Admin"])


class GroupsOutput(ActionOutput):
    id: float = OutputField(example_values=[4460341])
    name: str = OutputField(example_values=["test Example App"])


class AddGroupUserOutput(ActionOutput):
    adminUser: bool = OutputField(example_values=[True])
    deleted: bool = OutputField(example_values=[False])
    department: DepartmentOutput
    email: str = OutputField(example_values=["test 134@example.us"])
    groups: list[GroupsOutput]
    id: float = OutputField(example_values=[9840695])
    name: str = OutputField(example_values=["test Test user"])


@app.action(
    description="Add user to group",
    action_type="generic",
    read_only=False,
    verbose="Add a group to the user's profile.",
)
def add_group_user(
    params: AddGroupUserParams, soar: SOARClient, asset: Asset
) -> AddGroupUserOutput:
    raise NotImplementedError()


class RemoveGroupUserParams(Params):
    user_id: float = Param(
        description="ZScaler User Id", primary=True, cef_types=["zscaler user id"]
    )
    group_id: float = Param(
        description="ZScaler Group Id", primary=True, cef_types=["zscaler group id"]
    )


class DepartmentOutput(ActionOutput):
    id: float = OutputField(example_values=[4459551])
    name: str = OutputField(example_values=["test Service Admin"])


class GroupsOutput(ActionOutput):
    id: float = OutputField(example_values=[4459550])
    name: str = OutputField(example_values=["test Service Admin"])


class RemoveGroupUserOutput(ActionOutput):
    adminUser: bool = OutputField(example_values=[True])
    deleted: bool = OutputField(example_values=[False])
    department: DepartmentOutput
    email: str = OutputField(example_values=["test 134@example.us"])
    groups: list[GroupsOutput]
    id: float = OutputField(example_values=[9840695])
    name: str = OutputField(example_values=["test Elsie"])


@app.action(
    description="Remove user from group",
    action_type="correct",
    read_only=False,
    verbose="Remove a group from the user's profile.",
)
def remove_group_user(
    params: RemoveGroupUserParams, soar: SOARClient, asset: Asset
) -> RemoveGroupUserOutput:
    raise NotImplementedError()


class GetAllowlistOutput(ActionOutput):
    url: str


@app.action(description="Get urls on the allow list", action_type="investigate")
def get_allowlist(params: Params, soar: SOARClient, asset: Asset) -> GetAllowlistOutput:
    raise NotImplementedError()


class GetDenylistParams(Params):
    filter: str | None = Param(
        description="Filter results be url or ip",
        primary=True,
        value_list=["url", "ip"],
    )
    query: str | None = Param(
        description="Regular expression to match url or ip against", primary=True
    )


class GetDenylistOutput(ActionOutput):
    url: str


@app.action(description="Get urls on the deny list", action_type="investigate")
def get_denylist(
    params: GetDenylistParams, soar: SOARClient, asset: Asset
) -> GetDenylistOutput:
    raise NotImplementedError()


class UpdateUserParams(Params):
    user_id: float = Param(
        description="ZScaler User Id", primary=True, cef_types=["zscaler user id"]
    )
    user: str | None = Param(
        description="JSON object containing the user details (see https://help.zscaler.com/zia/user-management#/users/{userId}-put)",
        primary=True,
    )


class DepartmentOutput(ActionOutput):
    id: float = OutputField(example_values=[81896690])
    name: str = OutputField(example_values=["test IT"])


class GroupsOutput(ActionOutput):
    id: float = OutputField(cef_types=["zscaler group id"], example_values=[8894813])
    name: str = OutputField(example_values=["test Super Admin"])


class UpdateUserOutput(ActionOutput):
    adminUser: bool
    comments: str = OutputField(example_values=["test This is test user"])
    deleted: bool
    department: DepartmentOutput
    email: str = OutputField(
        cef_types=["email"], example_values=["test first.last@domain.com"]
    )
    groups: list[GroupsOutput]
    id: float = OutputField(cef_types=["zscaler user id"], example_values=[889814])
    name: str = OutputField(example_values=["test First Last"])


@app.action(
    description="Update user with given id", action_type="correct", read_only=False
)
def update_user(
    params: UpdateUserParams, soar: SOARClient, asset: Asset
) -> UpdateUserOutput:
    raise NotImplementedError()


class AddCategoryUrlParams(Params):
    category_id: str = Param(
        description="The ID of the category to add the specified URLs to", primary=True
    )
    urls: str | None = Param(
        description="A comma-separated list of URLs to add to the specified category",
        primary=True,
    )
    retaining_parent_category_url: str | None = Param(
        description="A comma-separated list of URLs to add to the retaining parent category section inside the specified category",
        primary=True,
        alias="retaining-parent-category-url",
    )


class ScopesOutput(ActionOutput):
    Type: str


class AddCategoryUrlOutput(ActionOutput):
    id: str
    val: float
    type: str
    urls: str
    scopes: list[ScopesOutput]
    editable: bool
    keywords: str
    description: str
    configuredName: str
    customCategory: bool
    customUrlsCount: float
    dbCategorizedUrls: str
    customIpRangesCount: float
    keywordsRetainingParentCategory: str
    urlsRetainingParentCategoryCount: float
    ipRangesRetainingParentCategoryCount: float


@app.action(description="Add urls to a cetgory", action_type="generic", read_only=False)
def add_category_url(
    params: AddCategoryUrlParams, soar: SOARClient, asset: Asset
) -> AddCategoryUrlOutput:
    raise NotImplementedError()


class AddCategoryIpParams(Params):
    category_id: str = Param(
        description="The ID of the category to add the specified URLs to", primary=True
    )
    ips: str | None = Param(
        description="A comma-separated list of IP addresses to add to the specified category",
        primary=True,
    )
    retaining_parent_category_ip: str | None = Param(
        description="A comma-separated list of IPs to add to the retaining parent category section inside the specified category",
        primary=True,
        alias="retaining-parent-category-ip",
    )


class ScopesOutput(ActionOutput):
    Type: str


class AddCategoryIpOutput(ActionOutput):
    id: str
    val: float
    type: str
    urls: str
    scopes: list[ScopesOutput]
    editable: bool
    keywords: str
    description: str
    configuredName: str
    customCategory: bool
    customUrlsCount: float
    dbCategorizedUrls: str
    customIpRangesCount: float
    keywordsRetainingParentCategory: str
    urlsRetainingParentCategoryCount: float
    ipRangesRetainingParentCategoryCount: float


@app.action(description="Add IPs to a cetgory", action_type="generic", read_only=False)
def add_category_ip(
    params: AddCategoryIpParams, soar: SOARClient, asset: Asset
) -> AddCategoryIpOutput:
    raise NotImplementedError()


class RemoveCategoryUrlParams(Params):
    category_id: str = Param(
        description="The ID of the category to add the specified URLs to", primary=True
    )
    urls: str | None = Param(
        description="A comma-separated list of URLs to remove from the specified category",
        primary=True,
    )
    retaining_parent_category_url: str | None = Param(
        description="A comma-separated list of URLs to remove from the retaining parent category section inside the specified category",
        primary=True,
        alias="retaining-parent-category-url",
    )


class ScopesOutput(ActionOutput):
    Type: str


class RemoveCategoryUrlOutput(ActionOutput):
    id: str
    val: float
    type: str
    urls: str
    scopes: list[ScopesOutput]
    editable: bool
    keywords: str
    description: str
    configuredName: str
    customCategory: bool
    customUrlsCount: float
    dbCategorizedUrls: str
    customIpRangesCount: float
    keywordsRetainingParentCategory: str
    urlsRetainingParentCategoryCount: float
    ipRangesRetainingParentCategoryCount: float


@app.action(description="Add urls to a cetgory", action_type="generic", read_only=False)
def remove_category_url(
    params: RemoveCategoryUrlParams, soar: SOARClient, asset: Asset
) -> RemoveCategoryUrlOutput:
    raise NotImplementedError()


class RemoveCategoryIpParams(Params):
    category_id: str = Param(
        description="The ID of the category to add the specified URLs to", primary=True
    )
    ips: str | None = Param(
        description="A comma-separated list of IP addresses to add to the specified category",
        primary=True,
    )
    retaining_parent_category_ip: str | None = Param(
        description="A comma-separated list of IPs to add to the retaining parent category section inside the specified category",
        primary=True,
        alias="retaining-parent-category-ip",
    )


class ScopesOutput(ActionOutput):
    Type: str


class RemoveCategoryIpOutput(ActionOutput):
    id: str
    val: float
    type: str
    urls: str
    scopes: list[ScopesOutput]
    editable: bool
    keywords: str
    description: str
    configuredName: str
    customCategory: bool
    customUrlsCount: float
    dbCategorizedUrls: str
    customIpRangesCount: float
    keywordsRetainingParentCategory: str
    urlsRetainingParentCategoryCount: float
    ipRangesRetainingParentCategoryCount: float


@app.action(
    description="Remove IPs to a cetgory", action_type="generic", read_only=False
)
def remove_category_ip(
    params: RemoveCategoryIpParams, soar: SOARClient, asset: Asset
) -> RemoveCategoryIpOutput:
    raise NotImplementedError()


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


@app.action(
    description="Create destination group", action_type="generic", read_only=False
)
def create_destination_group(
    params: CreateDestinationGroupParams, soar: SOARClient, asset: Asset
) -> CreateDestinationGroupOutput:
    raise NotImplementedError()


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


@app.action(
    description="List destination group", action_type="investigate", read_only=False
)
def list_destination_group(
    params: ListDestinationGroupParams, soar: SOARClient, asset: Asset
) -> ListDestinationGroupOutput:
    raise NotImplementedError()


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


@app.action(
    description="Edit destination group", action_type="generic", read_only=False
)
def edit_destination_group(
    params: EditDestinationGroupParams, soar: SOARClient, asset: Asset
) -> EditDestinationGroupOutput:
    raise NotImplementedError()


class DeleteDestinationGroupParams(Params):
    ip_group_ids: str | None = Param(
        description="A comma-separated list of unique identifiers for the IP destination groups",
        primary=True,
    )


class DeleteDestinationGroupOutput(ActionOutput):
    ip_group_ids: str


@app.action(
    description="Delete destination group", action_type="generic", read_only=False
)
def delete_destination_group(
    params: DeleteDestinationGroupParams, soar: SOARClient, asset: Asset
) -> DeleteDestinationGroupOutput:
    raise NotImplementedError()


class GetDepartmentsParams(Params):
    name: str | None = Param(description="Filter by department name", primary=True)
    page: float | None = Param(description="Specifies the page offset", primary=True)
    pageSize: float | None = Param(
        description="Specifies the page size", primary=True, default=100
    )


class GetDepartmentsOutput(ActionOutput):
    id: float
    name: str
    isNonEditable: bool


@app.action(description="Get a list of departments", action_type="investigate")
def get_departments(
    params: GetDepartmentsParams, soar: SOARClient, asset: Asset
) -> GetDepartmentsOutput:
    raise NotImplementedError()


class GetCategoryDetailsParams(Params):
    category_ids: str | None = Param(
        description="Comma seperated string of category id's to query", primary=True
    )


class ScopesOutput(ActionOutput):
    Type: str = OutputField(example_values=["test ORGANIZATION"])


class GetCategoryDetailsOutput(ActionOutput):
    configuredName: str = OutputField(example_values=["test Test-Caution"])
    customCategory: bool
    keywords: str
    urls: str
    customIpRangesCount: float = OutputField(example_values=[0])
    customUrlsCount: float = OutputField(example_values=[0])
    dbCategorizedUrls: str = OutputField(example_values=["test 6.5.3.2.4"])
    description: str = OutputField(
        example_values=["test OTHER_RESTRICTED_WEBSITE_DESC"]
    )
    editable: bool
    id: str = OutputField(
        cef_types=["zscaler url category"],
        example_values=["test OTHER_RESTRICTED_WEBSITE"],
    )
    ipRangesRetainingParentCategoryCount: float = OutputField(example_values=[0])
    scopes: list[ScopesOutput]
    type: str = OutputField(example_values=["test URL_CATEGORY"])
    urlsRetainingParentCategoryCount: float = OutputField(example_values=[0])
    val: float = OutputField(example_values=[1])


@app.action(
    description="Get the urls and keywords of a category", action_type="investigate"
)
def get_category_details(
    params: GetCategoryDetailsParams, soar: SOARClient, asset: Asset
) -> GetCategoryDetailsOutput:
    raise NotImplementedError()


if __name__ == "__main__":
    app.cli()
