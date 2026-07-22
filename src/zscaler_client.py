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
from zscaler import ZscalerClient

from .asset import Asset

SPLUNK_ZSCALER_PARTNER_ID = "ptr_O9IXHIjxsno4dij0GSExUY"
DEFAULT_REQUEST_TIMEOUT = 240
DEFAULT_MAX_RETRIES = 2


def get_client(asset: Asset) -> ZscalerClient:
    """Create the official Zscaler client from an asset."""
    return ZscalerClient(
        {
            "clientId": asset.client_id,
            "clientSecret": asset.client_secret,
            "vanityDomain": asset.vanity_domain,
            "cloud": asset.cloud,
            "sandboxToken": asset.sandbox_token or "",
            "sandboxCloud": asset.sandbox_cloud or "",
            "partnerId": SPLUNK_ZSCALER_PARTNER_ID,
            "requestTimeout": DEFAULT_REQUEST_TIMEOUT,
            "rateLimit": {"maxRetries": DEFAULT_MAX_RETRIES},
        }
    )
