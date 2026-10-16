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

# Cell 6: cell 2 plus Kata Containers as the kata RuntimeClass handler.
# Needs /dev/kvm: the VM is created with nested virtualisation.
. "$(dirname "$0")/common.sh"
. "$(dirname "$0")/ubuntu.sh"
KATA_VERSION=3.14.0
[ -c /dev/kvm ]
install_ubuntu_runtime "$UPDATES_CONTAINERD" "$UPDATES_RUNC"
apt-get install -y -q xz-utils
install_cni
install_crictl
curl -fsSL "https://github.com/kata-containers/kata-containers/releases/download/$KATA_VERSION/kata-static-$KATA_VERSION-amd64.tar.xz" | tar -xJ -C /
ln -sf /opt/kata/bin/containerd-shim-kata-v2 /usr/local/bin/
add_handler_v3 kata io.containerd.kata.v2
systemctl enable containerd
systemctl restart containerd
check_containerd 2.2.1
check_runc 1.3.4
/opt/kata/bin/kata-runtime --version | grep -F "$KATA_VERSION"
/opt/kata/bin/kata-runtime check --no-network-checks
check_handler kata
