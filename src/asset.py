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
from soar_sdk.asset import BaseAsset, AssetField


class Asset(BaseAsset):
    base_url: str = AssetField(
        description="Base URL (e.g. https://admin.zscaler_instance.net)"
    )
    api_key: str = AssetField(description="API Key")
    username: str = AssetField(description="Username")
    password: str = AssetField(description="Password")
    sandbox_base_url: str | None = AssetField(description="Sandbox Base URL")
    sandbox_api_token: str | None = AssetField(description="Sandbox API Token")
