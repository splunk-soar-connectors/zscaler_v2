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
from collections.abc import Callable
from typing import Any

import pytest
from soar_sdk.app import App
from soar_sdk.shims.phantom.encryption_helper import encryption_helper

from src.app import create_zscaler_soar_connector_app

from . import config as test_config


class RedactedAssetConfig(dict[str, str]):
    """Prevent live Zscaler credentials from appearing in pytest tracebacks."""

    def __repr__(self) -> str:
        return f"{type(self).__name__}(<redacted>)"


@pytest.fixture(scope="session", autouse=True)
def load_dotenv() -> None:
    test_config.load_dotenv_file()


@pytest.fixture(scope="session")
def live_asset_config(load_dotenv: None) -> RedactedAssetConfig:
    config = RedactedAssetConfig()
    missing: list[str] = []

    for asset_key, env_key in test_config.REQUIRED_ASSET_ENV_KEYS.items():
        value = os.environ.get(env_key)
        if value:
            config[asset_key] = value
        else:
            missing.append(env_key)

    if missing:
        raise AssertionError(
            "Missing required live test environment variables: " + ", ".join(missing)
        )

    for asset_key, env_key in test_config.OPTIONAL_ASSET_ENV_KEYS.items():
        if value := os.environ.get(env_key):
            config[asset_key] = value

    return config


@pytest.fixture
def connector_app() -> App:
    return create_zscaler_soar_connector_app()


@pytest.fixture
def build_soar_action_input(
    live_asset_config: dict[str, str],
) -> Callable[..., dict[str, Any]]:
    def _build_soar_action_input(
        *, action: str, parameters: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        asset_id = os.environ.get("SOAR_ASSET_ID", "123")
        asset_config = dict(live_asset_config)
        for sensitive_key in ("client_secret", "sandbox_token"):
            if value := asset_config.get(sensitive_key):
                asset_config[sensitive_key] = encryption_helper.encrypt(
                    value,
                    salt=asset_id,
                )

        return {
            "identifier": action,
            "action": action,
            "asset_id": asset_id,
            "container_id": int(os.environ.get("SOAR_CONTAINER_ID", "456")),
            "config": {
                "app_version": "1.0.0",
                "directory": ".",
                "main_module": "src.app:app",
                **asset_config,
            },
            "parameters": [parameters or {}],
        }

    return _build_soar_action_input
