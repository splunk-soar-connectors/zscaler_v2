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


class GetReportParams(Params):
    file_hash: str = Param(
        description="The md5 file hash", primary=True, cef_types=["md5"]
    )


class ClassificationOutput(ActionOutput):
    Category: str = OutputField(example_values=["test BENIGN"])
    DetectedMalware: str
    Score: float = OutputField(example_values=[10])
    Type: str = OutputField(example_values=["test BENIGN"])


class FilepropertiesOutput(ActionOutput):
    DigitalCerificate: str
    FileSize: float = OutputField(example_values=[350084])
    FileType: str = OutputField(example_values=["test EXE"])
    Issuer: str
    MD5: str = OutputField(
        cef_types=["md5"], example_values=["test 1043ca3fc2e83f0c6f100e46d2ea16be"]
    )
    RootCA: str
    SHA1: str = OutputField(
        cef_types=["sha1"],
        example_values=["test efbd493b33543341d43df6db4c92de2473cf49f3"],
    )
    SSDeep: str = OutputField(
        example_values=[
            "test 6144:IFkS+8dpN9EtEnROO4T0LbTbHiXuFW0XPBGunX9v62HCTAA1PSahJj3zDbSJ8:CkMy4TGWXuFR5JAxS6Lnbu8"
        ]
    )
    Sha256: str = OutputField(
        cef_types=["sha256"],
        example_values=[
            "test 0e7fd4dde827a7f0bda82bbfbce4b92a551d0cd296f72e936b8968310d2181cd"
        ],
    )


class OriginOutput(ActionOutput):
    Country: str = OutputField(example_values=["test United States"])
    Language: str = OutputField(example_values=["test English"])
    Risk: str = OutputField(example_values=["test LOW"])


class SummaryOutput(ActionOutput):
    Category: str = OutputField(example_values=["test EXECS"])
    Duration: float = OutputField(example_values=[524114])
    FileType: str = OutputField(example_values=["test EXE"])
    StartTime: float = OutputField(example_values=[1520334357])
    Status: str = OutputField(example_values=["test COMPLETED"])


class SystemsummaryOutput(ActionOutput):
    Risk: str = OutputField(example_values=["test LOW"])
    Signature: str = OutputField(
        example_values=["test Binary contains paths to development resources"]
    )
    SignatureSources: str = OutputField(example_values=["test no activity detected"])


class FullDetailsOutput(ActionOutput):
    Classification: ClassificationOutput
    FileProperties: FilepropertiesOutput
    Origin: OriginOutput
    Summary: SummaryOutput
    SystemSummary: list[SystemsummaryOutput]


class GetReportOutput(ActionOutput):
    Full_Details: FullDetailsOutput


def get_report(
    params: GetReportParams, soar: SOARClient, asset: Asset
) -> GetReportOutput:
    raise NotImplementedError()
