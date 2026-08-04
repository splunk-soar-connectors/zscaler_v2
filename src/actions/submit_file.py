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
import re

from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import OutputField, PermissiveActionOutput
from soar_sdk.exceptions import ActionFailure, SoarAPIError
from soar_sdk.logging import getLogger
from soar_sdk.models.vault_attachment import VaultAttachment
from soar_sdk.params import Param, Params

from ..asset import Asset
from ..zscaler_client import get_client

logger = getLogger()

_SUCCESS_MESSAGE = "Successfully submitted the file to Sandbox"
_SANDBOX_TOKEN_PATTERN = re.compile(
    r"([?&]api_token=)[^&\s'\"]+",
    flags=re.IGNORECASE,
)


class SubmitFileParams(Params):
    vault_id: str = Param(
        description="Vault ID of file to submit",
        primary=True,
        cef_types=["vault id", "sha1"],
    )
    force: bool | None = Param(
        description="Submit file to sandbox even if found malicious during AV scan and a verdict already exists"
    )


class SubmitFileOutput(PermissiveActionOutput):
    code: float | None = OutputField(example_values=[200])
    fileType: str | None = OutputField(example_values=["test zip"])
    md5: str | None = OutputField(
        cef_types=["md5"], example_values=["test 6CE6F415D8475545BE5BA114F208B0FF"]
    )
    message: str | None = OutputField(example_values=["test /submit response OK"])
    sandboxSubmission: str | None = OutputField(example_values=["test Virus"])
    virusName: str | None = OutputField(example_values=["test EICAR_Test_File"])
    virusType: str | None = OutputField(example_values=["test Virus"])


def _submission_message(submission: dict[str, object]) -> str:
    response_message = submission.get("message")
    sandbox_submission = submission.get("sandboxSubmission")
    if response_message == "/submit response OK":
        return _SUCCESS_MESSAGE

    details = [
        str(value)
        for value in (sandbox_submission, response_message)
        if value is not None and str(value)
    ]
    if len(details) == 2 and details[0].casefold() == details[1].casefold():
        details.pop()
    if not details:
        return _SUCCESS_MESSAGE

    code = submission.get("code")
    return f"Status Code: {code}. Data from server: {'. '.join(details)}"


def _redact_sandbox_token(error: object) -> str:
    """Remove Sandbox API tokens embedded in SDK request URLs."""
    return _SANDBOX_TOKEN_PATTERN.sub(r"\1<redacted>", str(error))


def _select_vault_attachment(
    attachments: list[VaultAttachment],
) -> VaultAttachment:
    if not attachments:
        raise RuntimeError("Vault file could not be found with the supplied vault ID")
    return min(attachments, key=lambda attachment: attachment.id)


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
        try:
            attachments = soar.vault.get_attachment(vault_id=params.vault_id)
        except SoarAPIError as exc:
            raise RuntimeError(
                "Vault file could not be found with the supplied vault ID"
            ) from exc
        attachment = _select_vault_attachment(attachments)
        with get_client(asset) as client:
            submission, response, error = client.zia.sandbox.submit_file(
                file_path=attachment.path,
                force=bool(params.force),
            )
            if error is not None:
                raise RuntimeError(f"Zscaler API error: {_redact_sandbox_token(error)}")
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
        safe_error = _redact_sandbox_token(exc)
        logger.error("Submit file failed: %s", safe_error)
        message = f"Submit file failed: {safe_error}"
        soar.set_message(message)
        raise ActionFailure(message) from exc

    soar.set_message(_submission_message(raw_submission))
    return SubmitFileOutput(**raw_submission)
