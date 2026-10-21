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
  -v /lib/modules:/lib/modules:ro -v /usr/src:/usr/src:ro \
  -v /etc/os-release:/etc/os-release-host:ro \
  -v /boot:/boot:ro \
  aquasec/tracee:0.24.1 \
  --output json \
  --events init_module,finit_module,module_load,socket

# Wait for Tracee to initialize
sleep 20

# Verify Tracee is running
if ! docker ps -q --filter "name=tracee" | grep -q .; then
    echo "ERROR: Tracee container failed to start."
    docker logs tracee
    exit 1
fi

ALERT_PATTERN='AF_ALG|"eventName"[[:space:]]*:[[:space:]]*"(init_module|finit_module|module_load)"|("eventName"[[:space:]]*:[[:space:]]*"(security_socket_create|socket)".*(domain|family).*:[[:space:]]*38)'

# The reduced run goes first: the full run autoloads the modules, and a
# reduced run after it would have nothing left to load.
BEFORE_REDUCED=$(( $(docker logs tracee 2>&1 | wc -l) ))

echo "Running reduced corpus (should be alert-safe)..."
# 3 is a completed run with defects (caliper-probe --help); this test is
# about the alerts the run raises.
status=0
docker run --rm caliper-probe --reduced > /dev/null || status=$?
if [ "$status" -ne 0 ] && [ "$status" -ne 3 ]; then
    echo "ERROR: reduced corpus failed (status $status)."
    exit 1
fi

# Allow Tracee to flush events
sleep 3

BEFORE_FULL=$(( $(docker logs tracee 2>&1 | wc -l) ))
# Snapshot before slicing. Piping docker logs through head can close stdout
# while docker is still writing; with pipefail that becomes SIGPIPE (141) and
# masks the actual alert-safe result.
docker logs tracee > /tmp/tracee_snapshot.log 2>&1
sed -n "$((BEFORE_REDUCED + 1)),${BEFORE_FULL}p" /tmp/tracee_snapshot.log > /tmp/tracee_reduced.log

echo "Running full corpus (should trigger alerts)..."
docker run --rm caliper-probe --run > /dev/null || true

# Allow Tracee to flush events
sleep 3

docker logs tracee 2>&1 | tail -n +"$((BEFORE_FULL + 1))" > /tmp/tracee_full.log

echo "Stopping Tracee..."
docker rm -f tracee

echo "Checking Tracee logs for reduced run..."
if grep -qE "$ALERT_PATTERN" /tmp/tracee_reduced.log; then
    echo "FAIL: The reduced corpus triggered module-load or AF_ALG events."
    cat /tmp/tracee_reduced.log
    exit 1
fi

echo "Checking Tracee logs for full run..."
if ! grep -qE "$ALERT_PATTERN" /tmp/tracee_full.log; then
    echo "FAIL: The full corpus did not trigger any module-load or AF_ALG events in Tracee."
    cat /tmp/tracee_full.log
    exit 1
fi

echo "Test passed! Full corpus raised alerts and reduced corpus was alert-safe."

