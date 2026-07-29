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
from src.actions.get_report import _unknown_report_message


def test_unknown_report_message_is_matched_case_insensitively() -> None:
    api_message = "MD5 is unknown or its analysis has not been completed"

    assert _unknown_report_message({"Full Details": api_message}) == api_message


def test_completed_report_is_not_treated_as_unknown() -> None:
    assert _unknown_report_message({"Full Details": {"Summary": {}}}) is None


def test_unknown_report_status_returns_oneapi_message() -> None:
    assert (
        _unknown_report_message(
            {
                "Full Details": {
                    "Summary": {
                        "Status": "CONTENT_NOTFOUND",
                        "Message": "Content lookup failed.",
                    }
                }
            }
        )
        == "Content lookup failed."
    )
