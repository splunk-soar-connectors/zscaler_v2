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
from soar_sdk.exceptions import ActionFailure
from soar_sdk.logging import getLogger
from soar_sdk.params import Param, Params

from ..asset import Asset
from ..zscaler_client import get_client

logger = getLogger()

_SUCCESS_MESSAGE = "Successfully submitted the file to Sandbox"


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
    if not asset.sandbox_token:
        message = "Sandbox API token is required to submit a file"
        soar.set_message(message)
        raise ActionFailure(message)
    if not asset.sandbox_cloud:
        message = "Sandbox cloud is required to submit a file"
        soar.set_message(message)
        raise ActionFailure(message)

    try:
        attachments = soar.vault.get_attachment(vault_id=params.vault_id)
        if not attachments:
            raise RuntimeError(
                "Vault file could not be found with the supplied vault ID"
            )
        if len(attachments) != 1:
            raise RuntimeError("The supplied vault ID resolved to multiple vault files")

        attachment = attachments[0]
        with get_client(asset) as client:
            submission, response, error = client.zia.sandbox.submit_file(
                file_path=attachment.path,
                force=bool(params.force),
            )
            if error is not None:
                raise RuntimeError(f"Zscaler API error: {error}")
            if submission is None or response is None:
                raise RuntimeError("Zscaler API returned no Sandbox submission")

            raw_submission = response.get_body()
            if not isinstance(raw_submission, dict):
                raise RuntimeError("Zscaler API returned an invalid Sandbox submission")

            code = raw_submission.get("code")
            if code != 200:
                detail = raw_submission.get("message") or "unknown error"
                raise RuntimeError(
                    f"Zscaler Sandbox returned status code {code}: {detail}"
                )
    except ActionFailure:
        raise
    except Exception as exc:
        logger.exception("Submit file failed")
        message = f"Submit file failed: {exc}"
        soar.set_message(message)
        raise ActionFailure(message) from exc

    soar.set_message(_SUCCESS_MESSAGE)
    return SubmitFileOutput(**raw_submission)
