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
from soar_sdk.action_results import ActionOutput, OutputField, PermissiveActionOutput
from soar_sdk.exceptions import ActionFailure
from soar_sdk.logging import getLogger
from soar_sdk.params import Param, Params

from ..asset import Asset
from ..zscaler_client import get_client

logger = getLogger()

_MD5_PATTERN = re.compile(r"^[0-9a-fA-F]{32}$")
_UNKNOWN_MD5_MESSAGE = "MD5 is unknown or its analysis has not been completed"
_SUCCESS_MESSAGE = "Sandbox report successfully fetched for the provided MD5 hash"


class GetReportParams(Params):
    file_hash: str = Param(
        description="The MD5 file hash", primary=True, cef_types=["md5"]
    )


class ClassificationOutput(ActionOutput):
    Category: str | None = OutputField(example_values=["test BENIGN"])
    DetectedMalware: str | None
    Score: float | None = OutputField(example_values=[10])
    Type: str | None = OutputField(example_values=["test BENIGN"])


class FilepropertiesOutput(ActionOutput):
    DigitalCerificate: str | None
    FileSize: float | None = OutputField(example_values=[350084])
    FileType: str | None = OutputField(example_values=["test EXE"])
    Issuer: str | None
    MD5: str | None = OutputField(
        cef_types=["md5"], example_values=["test 1043ca3fc2e83f0c6f100e46d2ea16be"]
    )
    RootCA: str | None
    SHA1: str | None = OutputField(
        cef_types=["sha1"],
        example_values=["test efbd493b33543341d43df6db4c92de2473cf49f3"],
    )
    SSDeep: str | None = OutputField(
        example_values=[
            "test 6144:IFkS+8dpN9EtEnROO4T0LbTbHiXuFW0XPBGunX9v62HCTAA1PSahJj3zDbSJ8:CkMy4TGWXuFR5JAxS6Lnbu8"
        ]
    )
    Sha256: str | None = OutputField(
        cef_types=["sha256"],
        example_values=[
            "test 0e7fd4dde827a7f0bda82bbfbce4b92a551d0cd296f72e936b8968310d2181cd"
        ],
    )


class OriginOutput(ActionOutput):
    Country: str | None = OutputField(example_values=["test United States"])
    Language: str | None = OutputField(example_values=["test English"])
    Risk: str | None = OutputField(example_values=["test LOW"])


class SummaryOutput(ActionOutput):
    Category: str | None = OutputField(example_values=["test EXECS"])
    Duration: float | None = OutputField(example_values=[524114])
    FileType: str | None = OutputField(example_values=["test EXE"])
    StartTime: float | None = OutputField(example_values=[1520334357])
    Status: str | None = OutputField(example_values=["test COMPLETED"])


class SystemsummaryOutput(ActionOutput):
    Risk: str | None = OutputField(example_values=["test LOW"])
    Signature: str | None = OutputField(
        example_values=["test Binary contains paths to development resources"]
    )
    SignatureSources: str | None = OutputField(
        example_values=["test no activity detected"]
    )


class FullDetailsOutput(ActionOutput):
    Classification: ClassificationOutput | None
    FileProperties: FilepropertiesOutput | None
    Origin: OriginOutput | None
    Summary: SummaryOutput | None
    SystemSummary: list[SystemsummaryOutput] | None


class GetReportOutput(PermissiveActionOutput):
    Full_Details: FullDetailsOutput | None = OutputField(alias="Full Details")


def _unknown_report_message(raw_report: dict[str, object]) -> str | None:
    """Return the API's unknown-report message when present."""
    full_details = raw_report.get("Full Details")
    if (
        isinstance(full_details, str)
        and _UNKNOWN_MD5_MESSAGE.casefold() in full_details.casefold()
    ):
        return full_details
    if isinstance(full_details, dict):
        summary = full_details.get("Summary")
        if isinstance(summary, dict) and summary.get("Status") == "CONTENT_NOTFOUND":
            message = summary.get("Message")
            return message if isinstance(message, str) else _UNKNOWN_MD5_MESSAGE
    return None


def get_report(
    params: GetReportParams, soar: SOARClient, asset: Asset
) -> GetReportOutput:
    if _MD5_PATTERN.fullmatch(params.file_hash) is None:
        message = "Invalid MD5 hash"
        soar.set_message(message)
        raise ActionFailure(message)

    try:
        with get_client(asset) as client:
            report, response, error = client.zia.sandbox.get_report(
                params.file_hash,
                report_details="full",
            )
            if error is not None:
                raise RuntimeError(f"Zscaler API error: {error}")
            if report is None or response is None:
                raise RuntimeError("Zscaler API returned no sandbox report")

            raw_report = response.get_body()
            if not isinstance(raw_report, dict):
                raise RuntimeError("Zscaler API returned an invalid sandbox report")
    except Exception as exc:
        logger.exception("Get sandbox report failed")
        message = f"Get sandbox report failed: {exc}"
        soar.set_message(message)
        raise ActionFailure(message) from exc

    if unknown_message := _unknown_report_message(raw_report):
        soar.set_message(unknown_message)
        raise ActionFailure(unknown_message)

    soar.set_message(_SUCCESS_MESSAGE)
    return GetReportOutput(**raw_report)
