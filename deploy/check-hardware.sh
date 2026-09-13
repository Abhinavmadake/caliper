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
#
# Confirms the host can run the amd64 cells, including the Kata cell (#52,
# proposal §11.1). Exit 0 means yes.
set -euo pipefail

arch=$(uname -m)
[ "$arch" = x86_64 ] || { echo "need x86_64, got $arch" >&2; exit 1; }

[ -c /dev/kvm ] || { echo "/dev/kvm missing: no hardware virtualisation (or nested virt is off)" >&2; exit 1; }
[ -r /dev/kvm ] && [ -w /dev/kvm ] || { echo "/dev/kvm not accessible: add yourself to the kvm group" >&2; exit 1; }

flags=$(grep -c -E '(vmx|svm)' /proc/cpuinfo || true)
[ "$flags" -gt 0 ] || { echo "no vmx/svm flag in /proc/cpuinfo" >&2; exit 1; }

echo "ok: x86_64, /dev/kvm present and accessible, $flags CPU(s) with vmx/svm"
