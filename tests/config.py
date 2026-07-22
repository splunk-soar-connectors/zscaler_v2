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
import os
from pathlib import Path


APP_ROOT = Path(__file__).resolve().parents[1]
ENV_FILE = APP_ROOT / ".env"

REQUIRED_ASSET_ENV_KEYS = {
    "vanity_domain": "ZSCALER_VANITY_DOMAIN",
    "client_id": "ZSCALER_CLIENT_ID",
    "client_secret": "ZSCALER_CLIENT_SECRET",  # pragma: allowlist secret
}
OPTIONAL_ASSET_ENV_KEYS = {
    "cloud": "ZSCALER_CLOUD",
    "sandbox_token": "ZSCALER_SANDBOX_TOKEN",
    "sandbox_cloud": "ZSCALER_SANDBOX_CLOUD",
}


def load_dotenv_file() -> None:
    """Load local .env values without overriding explicit environment values."""
    if not ENV_FILE.exists():
        return

    for raw_line in ENV_FILE.read_text().splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip("'\""))
