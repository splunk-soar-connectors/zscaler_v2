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


def submit_file(
    params: SubmitFileParams, soar: SOARClient, asset: Asset
) -> SubmitFileOutput:
    raise NotImplementedError()
