#!/usr/bin/env bash
# Copyright 2026 Abhinav Ajit Madake, Sahil Tatyabhau Waje,
# Ritesh Aresh Saindane, Yogesh Babaji Palve
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

set -euo pipefail

if [[ $# -ne 1 || ! -x "$1" ]]; then
    echo "usage: $0 executable-caliper-probe" >&2
    exit 2
fi

binary=$1
start=$(date +%s%N)
if timeout --signal=TERM --kill-after=1s 5s "$binary" --reduced > /dev/null; then
    :
else
    status=$?
    echo "reduced corpus failed or exceeded its 5-second budget (status $status)" >&2
    exit 1
fi
end=$(date +%s%N)
elapsed_ms=$(((end - start) / 1000000))
printf 'reduced corpus completed in %d ms (budget: under 5000 ms)\n' "$elapsed_ms"
if (( elapsed_ms >= 5000 )); then
    echo "reduced corpus exceeded its 5-second budget" >&2
    exit 1
fi
