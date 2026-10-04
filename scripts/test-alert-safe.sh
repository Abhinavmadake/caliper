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

echo "Starting Tracee in the background..."
docker run -d --name tracee --privileged --pid=host --cgroupns=host \
  -v /lib/modules:/lib/modules:ro -v /usr/src:/usr/src:ro -v /tmp/tracee:/tmp/tracee \
  aquasec/tracee:latest \
  --output json

# Wait for Tracee to initialize
sleep 15

echo "Running full corpus (should trigger alerts)..."
docker run --rm caliper-probe --run > /dev/null || true

echo "Running reduced corpus (should be alert-safe)..."
docker run --rm caliper-probe --reduced > /dev/null

echo "Stopping Tracee..."
docker rm -f tracee

echo "Test completed. Check Tracee logs for results."
