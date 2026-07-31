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
import time

import pytest
import regex

from src.actions.get_denylist import _matches_query


def test_matches_query_accepts_a_normal_pattern() -> None:
    pattern = regex.compile(r".*example\.com")

    assert _matches_query(
        pattern,
        "www.example.com",
        deadline=time.monotonic() + 1,
    )


def test_matches_query_bounds_catastrophic_backtracking() -> None:
    pattern = regex.compile(r"(a|aa)+$")

    with pytest.raises(RuntimeError, match="5-second evaluation limit"):
        _matches_query(
            pattern,
            ("a" * 10_000) + "!",
            deadline=time.monotonic() + 0.001,
        )
