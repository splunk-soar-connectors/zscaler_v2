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
import secrets
from collections.abc import Callable
from collections.abc import Iterator
from typing import Any, TypedDict
from uuid import uuid4

import pytest
from soar_sdk.app import App
from soar_sdk.shims.phantom.encryption_helper import encryption_helper

from src.app import create_zscaler_soar_connector_app
from src.asset import Asset
from src.zscaler_client import get_client

from . import config as test_config


class RedactedAssetConfig(dict[str, str]):
    """Prevent live Zscaler credentials from appearing in pytest tracebacks."""

    def __repr__(self) -> str:
        return f"{type(self).__name__}(<redacted>)"


class ManagedZiaTestIdentity(TypedDict):
    """Identifiers for ZIA resources owned by the live test session."""

    user_id: int
    target_group_id: int
    base_group_id: int
    department_id: int
    user_name: str
    user_email: str
    user_comments: str


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


@pytest.fixture(scope="session")
def managed_zia_test_identity(
    live_asset_config: dict[str, str],
) -> Iterator[ManagedZiaTestIdentity]:
    """Create an isolated ZIA identity and remove it after the live test session."""
    domain = os.environ.get("ZSCALER_TEST_DOMAIN", "").strip().removeprefix("@")
    assert domain, "ZSCALER_TEST_DOMAIN must be a registered ZIA tenant domain"
    assert "@" not in domain, "ZSCALER_TEST_DOMAIN must contain only the domain"

    asset = Asset.model_validate(live_asset_config)
    suffix = uuid4().hex
    department_id: int | None = None
    base_group_id: int | None = None
    target_group_id: int | None = None
    user_id: int | None = None
    user_name = f"PAPP-38277 user {suffix}"
    user_email = f"papp-38277-{suffix}@{domain}"
    user_comments = "Temporary resource created by zscaler_v2 live tests"
    cleanup_errors: list[str] = []

    with get_client(asset) as client:
        try:
            department, _response, error = client.zia.user_management.add_department(
                name=f"PAPP-38277 department {suffix}",
                comments="Temporary resource created by zscaler_v2 live tests",
            )
            assert error is None, f"Unable to create test department: {error}"
            assert department is not None
            assert department.id is not None
            department_id = int(department.id)

            base_group, _response, error = client.zia.user_management.add_group(
                name=f"PAPP-38277 base group {suffix}",
                comments="Temporary resource created by zscaler_v2 live tests",
            )
            assert error is None, f"Unable to create base test group: {error}"
            assert base_group is not None
            assert base_group.id is not None
            base_group_id = int(base_group.id)

            target_group, _response, error = client.zia.user_management.add_group(
                name=f"PAPP-38277 target group {suffix}",
                comments="Temporary resource created by zscaler_v2 live tests",
            )
            assert error is None, f"Unable to create target test group: {error}"
            assert target_group is not None
            assert target_group.id is not None
            target_group_id = int(target_group.id)

            user, _response, error = client.zia.user_management.add_user(
                name=user_name,
                email=user_email,
                groups=[{"id": base_group_id}],
                department={"id": department_id},
                comments=user_comments,
                password=f"Zia!9aA-{secrets.token_urlsafe(24)}",
            )
            assert error is None, f"Unable to create test user: {error}"
            assert user is not None
            assert user.id is not None
            user_id = int(user.id)

            yield {
                "user_id": user_id,
                "target_group_id": target_group_id,
                "base_group_id": base_group_id,
                "department_id": department_id,
                "user_name": user_name,
                "user_email": user_email,
                "user_comments": user_comments,
            }
        finally:
            if user_id is not None:
                _result, _response, error = client.zia.user_management.delete_user(
                    str(user_id)
                )
                if error is not None:
                    cleanup_errors.append(f"user {user_id}: {error}")

            for group_id in (target_group_id, base_group_id):
                if group_id is None:
                    continue
                _result, _response, error = client.zia.user_management.delete_group(
                    group_id
                )
                if error is not None:
                    cleanup_errors.append(f"group {group_id}: {error}")

            if department_id is not None:
                _result, _response, error = (
                    client.zia.user_management.delete_department(department_id)
                )
                if error is not None:
                    cleanup_errors.append(f"department {department_id}: {error}")

    assert not cleanup_errors, "Unable to clean up live-test resources: " + "; ".join(
        cleanup_errors
    )


@pytest.fixture
def connector_app() -> App:
    return create_zscaler_soar_connector_app()


@pytest.fixture
def offline_asset_config() -> RedactedAssetConfig:
    return RedactedAssetConfig(
        vanity_domain="offline-test",
        client_id="offline-client",
        client_secret="offline-secret",  # pragma: allowlist secret
        cloud="PRODUCTION",
    )


def _action_input_builder(
    asset_config: dict[str, str],
) -> Callable[..., dict[str, Any]]:
    def _build_soar_action_input(
        *, action: str, parameters: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        asset_id = os.environ.get("SOAR_ASSET_ID", "123")
        encrypted_asset_config = dict(asset_config)
        for sensitive_key in ("client_secret",):
            if value := encrypted_asset_config.get(sensitive_key):
                encrypted_asset_config[sensitive_key] = encryption_helper.encrypt(
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
                **encrypted_asset_config,
            },
            "parameters": [parameters or {}],
        }

    return _build_soar_action_input


@pytest.fixture
def build_soar_action_input(
    offline_asset_config: dict[str, str],
) -> Callable[..., dict[str, Any]]:
    return _action_input_builder(offline_asset_config)


@pytest.fixture
def build_live_soar_action_input(
    live_asset_config: dict[str, str],
) -> Callable[..., dict[str, Any]]:
    return _action_input_builder(live_asset_config)
