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
from soar_sdk.logging import getLogger

from .actions import register_actions
from .asset import Asset

logger = getLogger()


def create_zscaler_soar_connector_app() -> App:
    """Create and configure the Zscaler v2 connector app."""
    return App(
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


app = create_zscaler_soar_connector_app()


@app.test_connectivity()
def test_connectivity(soar: SOARClient, asset: Asset) -> None:
    raise NotImplementedError()


app = register_actions(app)


if __name__ == "__main__":
    app.cli()
