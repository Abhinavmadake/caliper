#!/usr/bin/env bash
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

# Cell 4: cell 2 with the noble release pocket's containerd 1.7.12 + runc
# 1.1.12, whose RuntimeDefault predates the io_uring and AF_ALG denies.
# Same image as cell 2, so the runtime is the only axis that moves.
. "$(dirname "$0")/common.sh"
. "$(dirname "$0")/ubuntu.sh"
install_ubuntu_runtime "$RELEASE_CONTAINERD" "$RELEASE_RUNC"
install_cni
install_crictl
systemctl enable --now containerd
check_containerd 1.7.12
check_runc 1.1.12
