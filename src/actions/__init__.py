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
from collections.abc import Callable
from typing import Any, cast

from soar_sdk.app import App
from soar_sdk.types import NamedCallable

from .get_report import get_report
from .list_url_categories import list_url_categories
from .block_ip import block_ip
from .block_url import block_url
from .unblock_ip import unblock_ip
from .unblock_url import unblock_url
from .allow_ip import allow_ip
from .allow_url import allow_url
from .unallow_ip import unallow_ip
from .unallow_url import unallow_url
from .lookup_ip import lookup_ip
from .lookup_url import lookup_url
from .submit_file import submit_file
from .get_admin_users import get_admin_users
from .get_users import get_users
from .get_groups import get_groups
from .add_group_user import add_group_user
from .remove_group_user import remove_group_user
from .get_allowlist import get_allowlist
from .get_denylist import get_denylist
from .update_user import update_user
from .add_category_url import add_category_url
from .add_category_ip import add_category_ip
from .remove_category_url import remove_category_url
from .remove_category_ip import remove_category_ip
from .create_destination_group import create_destination_group
from .list_destination_group import list_destination_group
from .edit_destination_group import edit_destination_group
from .delete_destination_group import delete_destination_group
from .get_departments import get_departments
from .get_category_details import get_category_details


def _register_action(
    app: App,
    *,
    action: Callable[..., Any],
    description: str,
    action_type: str,
    read_only: bool = True,
    verbose: str = "",
) -> None:
    """Register an action while adapting to the SDK NamedCallable protocol."""
    app.register_action(
        action=cast(NamedCallable, action),
        description=description,
        action_type=action_type,
        read_only=read_only,
        verbose=verbose,
    )


def register_actions(app: App) -> App:
    """Register the extracted Zscaler v2 actions.

    Args:
        app: SOAR SDK app instance.

    Returns:
        The app with its extracted actions registered.
    """
    _register_action(
        app,
        action=get_report,
        description="Fetch sandbox report for provided md5 file hash",
        action_type="investigate",
    )

    _register_action(
        app,
        action=list_url_categories,
        description="List all URL categories",
        action_type="investigate",
    )

    _register_action(
        app,
        action=block_ip,
        description="Block an IP",
        action_type="contain",
        read_only=False,
        verbose="If a <b>url_category</b> is specified, it will add the IP(s) as a rule to that category. If it is left blank, it will instead add the IP(s) to the global blocklist.",
    )

    _register_action(
        app,
        action=block_url,
        description="Block a URL",
        action_type="contain",
        read_only=False,
        verbose="If a <b>url_category</b> is specified, it will add the URL(s) as a rule to that category. If it is left blank, it will instead add the URL(s) to the global blocklist.",
    )

    _register_action(
        app,
        action=unblock_ip,
        description="Unblock an IP",
        action_type="correct",
        read_only=False,
        verbose="If a <b>url_category</b> is specified, it will remove the IP(s) from that category. If it is left blank, it will instead remove the IP(s) from the global blocklist.",
    )

    _register_action(
        app,
        action=unblock_url,
        description="Unblock a URL",
        action_type="correct",
        read_only=False,
        verbose="If a <b>url_category</b> is specified, it will remove the URL(s) from that category. If it is left blank, it will instead remove the URL(s) from the global blocklist.",
    )

    _register_action(
        app,
        action=allow_ip,
        description="Add an IP address to the allowlist",
        action_type="contain",
        read_only=False,
        verbose="If a <b>url_category</b> is specified, it will add the IP(s) as a rule to that category. If it is left blank, it will instead add this IP(s) to the global allowlist.",
    )

    _register_action(
        app,
        action=allow_url,
        description="Add a URL to the allowed list",
        action_type="contain",
        read_only=False,
        verbose="If a <b>url_category</b> is specified, it will add the URL(s) as a rule to that category. If it is left blank, it will instead add the URL(s) to the global allowed list.",
    )

    _register_action(
        app,
        action=unallow_ip,
        description="Remove an IP address from the allowlist",
        action_type="correct",
        read_only=False,
        verbose="If a <b>url_category</b> is specified, it will remove the IP(s) from that category. If it is left blank, it will instead remove the IP(s) from the global allowlist.",
    )

    _register_action(
        app,
        action=unallow_url,
        description="Remove a URL from the allowed list",
        action_type="correct",
        read_only=False,
        verbose="If a <b>url_category</b> is specified, it will remove the URL(s) from that category. If it is left blank, it will instead remove the URL(s) from the global allowed list.",
    )

    _register_action(
        app,
        action=lookup_ip,
        description="Lookup the categories related to an IP",
        action_type="investigate",
    )

    _register_action(
        app,
        action=lookup_url,
        description="Lookup the categories related to a URL",
        action_type="investigate",
    )

    _register_action(
        app,
        action=submit_file,
        description="Submit a file to Zscaler Sandbox",
        action_type="generic",
        read_only=False,
        verbose="This action requires a Sandbox Submission API token. By default, files are scanned by Zscaler antivirus (AV) and submitted directly to the sandbox in order to obtain a verdict. However, if a verdict already exists for the file, you can use the 'force' parameter to make the sandbox to reanalyze it. You can submit up to 100 files per day.",
    )

    _register_action(
        app,
        action=get_admin_users,
        description="Get a list of admin users",
        action_type="investigate",
    )

    _register_action(
        app,
        action=get_users,
        description="Gets a list of all users and allows user filtering by name, department, or group",
        action_type="investigate",
        verbose="Gets a list of all users and allows user filtering by name, department, or group. The name search parameter performs a partial match. The dept and group parameters perform a 'starts with' match.",
    )

    _register_action(
        app,
        action=get_groups,
        description="Gets a list of groups",
        action_type="investigate",
        verbose="Gets a list of groups. The search parameters find matching values in the name or comments attributes.",
    )

    _register_action(
        app,
        action=add_group_user,
        description="Add user to group",
        action_type="generic",
        read_only=False,
        verbose="Add a group to the user's profile.",
    )

    _register_action(
        app,
        action=remove_group_user,
        description="Remove user from group",
        action_type="correct",
        read_only=False,
        verbose="Remove a group from the user's profile.",
    )

    _register_action(
        app,
        action=get_allowlist,
        description="Get urls on the allow list",
        action_type="investigate",
    )

    _register_action(
        app,
        action=get_denylist,
        description="Get urls on the deny list",
        action_type="investigate",
    )

    _register_action(
        app,
        action=update_user,
        description="Update user with given id",
        action_type="correct",
        read_only=False,
    )

    _register_action(
        app,
        action=add_category_url,
        description="Add urls to a cetgory",
        action_type="generic",
        read_only=False,
    )

    _register_action(
        app,
        action=add_category_ip,
        description="Add IPs to a cetgory",
        action_type="generic",
        read_only=False,
    )

    _register_action(
        app,
        action=remove_category_url,
        description="Add urls to a cetgory",
        action_type="generic",
        read_only=False,
    )

    _register_action(
        app,
        action=remove_category_ip,
        description="Remove IPs to a cetgory",
        action_type="generic",
        read_only=False,
    )

    _register_action(
        app,
        action=create_destination_group,
        description="Create destination group",
        action_type="generic",
        read_only=False,
    )

    _register_action(
        app,
        action=list_destination_group,
        description="List destination group",
        action_type="investigate",
        read_only=False,
    )

    _register_action(
        app,
        action=edit_destination_group,
        description="Edit destination group",
        action_type="generic",
        read_only=False,
    )

    _register_action(
        app,
        action=delete_destination_group,
        description="Delete destination group",
        action_type="generic",
        read_only=False,
    )

    _register_action(
        app,
        action=get_departments,
        description="Get a list of departments",
        action_type="investigate",
    )

    _register_action(
        app,
        action=get_category_details,
        description="Get the urls and keywords of a category",
        action_type="investigate",
    )

    return app
