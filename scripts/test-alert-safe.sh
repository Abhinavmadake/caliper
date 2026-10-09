#!/bin/bash
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

# This script verifies that the alert-safe reduced corpus does not trigger
# standard runtime security alerts, using Tracee as the monitor.

cleanup() {
  docker rm -f tracee > /dev/null 2>&1 || true
  rm -f /tmp/tracee_*.log
}
trap cleanup EXIT

echo "Starting Tracee in the background..."
docker run -d --name tracee --privileged --pid=host --cgroupns=host \
  -v /lib/modules:/lib/modules:ro -v /usr/src:/usr/src:ro -v /tmp/tracee:/tmp/tracee \
  aquasec/tracee:0.19.3 \
  --output json

# Wait for Tracee to initialize
sleep 15

echo "Running full corpus (should trigger alerts)..."
docker run --rm caliper-probe --run > /dev/null || true

# Mark the log position
BEFORE_LINES=$(docker logs tracee 2>&1 | wc -l)

echo "Running reduced corpus (should be alert-safe)..."
docker run --rm caliper-probe --reduced > /dev/null

# Capture only the new events emitted during the reduced corpus run
docker logs tracee 2>&1 | tail -n +"$((BEFORE_LINES + 1))" > /tmp/tracee_reduced.log

echo "Stopping Tracee..."
docker rm -f tracee

echo "Checking Tracee logs for module-load or AF_ALG events..."
if grep -qE '"eventName"[[:space:]]*:[[:space:]]*"(init_module|finit_module|module_load)"' /tmp/tracee_reduced.log || \
   grep -qE 'AF_ALG|"family"[[:space:]]*:[[:space:]]*38' /tmp/tracee_reduced.log; then
    echo "FAIL: The reduced corpus triggered module-load or AF_ALG events."
    cat /tmp/tracee_reduced.log
    exit 1
fi

echo "Test passed! No AF_ALG or module-load events detected."

