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
# mypy: disable-error-code=arg-type

# SOAR SDK's NamedCallable protocol declares function.__globals__ as writable,
# so mypy rejects ordinary action functions even though App.register_action
# accepts them at runtime.
from soar_sdk.app import App
from soar_sdk.meta.actions import ActionLock

from .get_report import get_report
from .list_url_categories import ListUrlCategoriesSummary, list_url_categories
from .block_web_destination import (
    BlockWebDestinationSummary,
    block_web_destination,
)
from .remove_blocked_web_destination import (
    RemoveBlockedWebDestinationSummary,
    remove_blocked_web_destination,
)
from .allow_web_destination import (
    AllowWebDestinationSummary,
    allow_web_destination,
)
from .remove_allowed_web_destination import (
    RemoveAllowedWebDestinationSummary,
    remove_allowed_web_destination,
)
from .lookup_web_destination import lookup_web_destination
from .submit_file import submit_file
from .get_admin_users import GetAdminUsersSummary, get_admin_users
from .get_users import GetUsersSummary, get_users
from .get_groups import GetGroupsSummary, get_groups
from .add_group_user import add_user_to_group
from .remove_group_user import remove_user_from_group
from .get_allowlist import GetAllowlistSummary, get_allowlist
from .get_denylist import GetDenylistSummary, get_denylist
from .update_user import update_user
from .add_category_destination import add_category_destination
from .remove_category_destination import remove_category_destination
from .create_destination_group import create_destination_group
from .list_destination_group import (
    ListDestinationGroupSummary,
    list_destination_group,
)
from .edit_destination_group import edit_destination_group
from .delete_destination_group import (
    DeleteDestinationGroupSummary,
    delete_destination_group,
)
from .get_departments import GetDepartmentsSummary, get_departments
from .get_category_details import GetCategoryDetailsSummary, get_category_details
from .make_request import make_request


_ASSET_MUTATION_LOCK = ActionLock()


def register_actions(app: App) -> App:
    """Register the extracted Zscaler v2 actions.

    Args:
        app: SOAR SDK app instance.

    Returns:
        The app with its extracted actions registered.
    """
    app.register_action(
        action=get_report,
        description="Fetch a sandbox report for the provided MD5 file hash",
        action_type="investigate",
    )

    app.register_action(
        action=list_url_categories,
        description="List all URL categories",
        action_type="investigate",
        render_as="table",
        summary_type=ListUrlCategoriesSummary,
    )

    app.register_action(
        action=block_web_destination,
        description="Add web destinations to the global blocklist",
        action_type="contain",
        read_only=False,
        lock=_ASSET_MUTATION_LOCK,
        summary_type=BlockWebDestinationSummary,
        verbose=(
            "Adds URLs, domains, IPv4 addresses, and IPv6 addresses to the "
            "global ZIA blocklist. HTTP and HTTPS schemes are removed before "
            "submission."
        ),
    )

    app.register_action(
        action=remove_blocked_web_destination,
        description="Remove web destinations from the global blocklist",
        action_type="correct",
        read_only=False,
        lock=_ASSET_MUTATION_LOCK,
        summary_type=RemoveBlockedWebDestinationSummary,
        verbose=(
            "Removes URLs, domains, IPv4 addresses, and IPv6 addresses from the "
            "global ZIA blocklist. HTTP and HTTPS schemes are removed before submission."
        ),
    )

    app.register_action(
        action=allow_web_destination,
        description="Add web destinations to the global allowlist",
        action_type="contain",
        read_only=False,
        lock=_ASSET_MUTATION_LOCK,
        summary_type=AllowWebDestinationSummary,
        verbose=(
            "Adds URLs, domains, IPv4 addresses, and IPv6 addresses to the "
            "global ZIA allowlist. HTTP and HTTPS schemes are removed before "
            "submission."
        ),
    )

    app.register_action(
        action=remove_allowed_web_destination,
        description="Remove web destinations from the global allowlist",
        action_type="correct",
        read_only=False,
        lock=_ASSET_MUTATION_LOCK,
        summary_type=RemoveAllowedWebDestinationSummary,
        verbose=(
            "Removes URLs, domains, IPv4 addresses, and IPv6 addresses from the "
            "global ZIA allowlist. HTTP and HTTPS schemes are removed before submission."
        ),
    )

    app.register_action(
        action=lookup_web_destination,
        description="Look up ZIA classifications for web destinations",
        action_type="investigate",
        render_as="table",
    )

    app.register_action(
        action=submit_file,
        description="Submit a file to Zscaler Sandbox",
        action_type="generic",
        read_only=False,
        verbose="This action requires a Sandbox Submission API token. By default, Zscaler antivirus (AV) scans files before submitting them to the sandbox for a verdict. If a verdict already exists, set the 'force' parameter to make the sandbox analyze the file again. You can submit up to 100 files per day.",
    )

    app.register_action(
        action=get_admin_users,
        description="Get a list of admin users",
        action_type="investigate",
        render_as="table",
        summary_type=GetAdminUsersSummary,
    )

    app.register_action(
        action=get_users,
        description="Get users, optionally filtered by name, department, or group",
        action_type="investigate",
        render_as="table",
        summary_type=GetUsersSummary,
        verbose="Get users, optionally filtered by name, department, or group. The name parameter performs a partial match. The department and group parameters perform a 'starts with' match.",
    )

    app.register_action(
        action=get_groups,
        description="Get a list of groups",
        action_type="investigate",
        render_as="table",
        summary_type=GetGroupsSummary,
        verbose="Get groups whose name or comments match the search parameter.",
    )

    app.register_action(
        action=add_user_to_group,
        description="Add a user to a group",
        action_type="generic",
        read_only=False,
        lock=_ASSET_MUTATION_LOCK,
        verbose="Add a group to the user's profile.",
    )

    app.register_action(
        action=remove_user_from_group,
        description="Remove a user from a group",
        action_type="correct",
        read_only=False,
        lock=_ASSET_MUTATION_LOCK,
        verbose="Remove a group from the user's profile.",
    )

    app.register_action(
        action=get_allowlist,
        description="Get web destinations on the allowlist",
        action_type="investigate",
        render_as="table",
        summary_type=GetAllowlistSummary,
    )

    app.register_action(
        action=get_denylist,
        description="Get web destinations on the denylist",
        action_type="investigate",
        render_as="table",
        summary_type=GetDenylistSummary,
    )

    app.register_action(
        action=update_user,
        description="Update the user with the specified ID",
        action_type="correct",
        read_only=False,
        lock=_ASSET_MUTATION_LOCK,
    )

    app.register_action(
        action=add_category_destination,
        description="Add web destinations to a custom URL category",
        action_type="generic",
        read_only=False,
        lock=_ASSET_MUTATION_LOCK,
    )

    app.register_action(
        action=remove_category_destination,
        description="Remove web destinations from a custom URL category",
        action_type="generic",
        read_only=False,
        lock=_ASSET_MUTATION_LOCK,
    )

    app.register_action(
        action=create_destination_group,
        description="Create a destination group",
        action_type="generic",
        read_only=False,
        lock=_ASSET_MUTATION_LOCK,
    )

    app.register_action(
        action=list_destination_group,
        description="List destination groups",
        action_type="investigate",
        read_only=True,
        render_as="table",
        summary_type=ListDestinationGroupSummary,
    )

    app.register_action(
        action=edit_destination_group,
        description="Edit a destination group",
        action_type="generic",
        read_only=False,
        lock=_ASSET_MUTATION_LOCK,
    )

    app.register_action(
        action=delete_destination_group,
        description="Delete destination groups",
        action_type="generic",
        read_only=False,
        lock=_ASSET_MUTATION_LOCK,
        summary_type=DeleteDestinationGroupSummary,
    )

    app.register_action(
        action=get_departments,
        description="Get a list of departments",
        action_type="investigate",
        render_as="table",
        summary_type=GetDepartmentsSummary,
    )

    app.register_action(
        action=get_category_details,
        description="Get the URLs and keywords of a category",
        action_type="investigate",
        render_as="table",
        summary_type=GetCategoryDetailsSummary,
    )

    make_request_action = app.make_request()(make_request)
    make_request_action.meta.description = (
        "Send an authenticated request to a ZIA OneAPI endpoint"
    )
    make_request_action.meta.verbose = (
        "Sends an authenticated request using the asset's Zscaler OneAPI OAuth "
        "credentials. Provide a relative /zia/api/v1 path; full URLs and Sandbox "
        "endpoints are not accepted. Mutating requests do not automatically activate "
        "pending ZIA changes."
    )
    make_request_action.meta.lock = _ASSET_MUTATION_LOCK

    return app
