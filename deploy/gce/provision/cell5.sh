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

# Cell 5: cell 2 plus gVisor as the runsc RuntimeClass handler.
. "$(dirname "$0")/common.sh"
. "$(dirname "$0")/ubuntu.sh"
GVISOR_RELEASE=20261005
install_ubuntu_runtime "$UPDATES_CONTAINERD" "$UPDATES_RUNC"
install_cni
install_crictl
apt-get install -y -q bzip2
base=https://storage.googleapis.com/gvisor/releases/release/$GVISOR_RELEASE/$(uname -m)
cd /tmp
curl -fsSLO "$base/gvisor.tar.bz2"
curl -fsSLO "$base/gvisor.tar.bz2.sha512"
echo "$(cut -d' ' -f1 gvisor.tar.bz2.sha512)  gvisor.tar.bz2" | sha512sum -c
# runsc, its containerd shim, and the gvisor-bin helpers it runs beside it.
tar -xjf gvisor.tar.bz2 -C /usr/local/bin
add_handler_v3 runsc io.containerd.runsc.v1
systemctl enable containerd
systemctl restart containerd
check_containerd 2.2.1
check_runc 1.3.4
runsc --version | grep -F "release-$GVISOR_RELEASE"
check_handler runsc
