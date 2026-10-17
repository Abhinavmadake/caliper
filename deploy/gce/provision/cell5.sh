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

# Cell 5: cell 2 plus gVisor as the runsc RuntimeClass handler.
. "$(dirname "$0")/common.sh"
. "$(dirname "$0")/ubuntu.sh"
GVISOR_RELEASE=20261005.0
GVISOR_SHA512=79869ae9a589355a46d46fdac068d9a954e741741ffe77c64e38c56ea955498c1cb04e9bce44e1cce5155333e6b76bee72347c6661bb7c78fd2fe3aad198c8fe
install_ubuntu_runtime "$UPDATES_CONTAINERD" "$UPDATES_RUNC"
apt-get install -y -q bzip2
install_cni
install_crictl
tarball=$(mktemp)
curl -fsSL -o "$tarball" "https://storage.googleapis.com/gvisor/releases/release/$GVISOR_RELEASE/$(uname -m)/gvisor.tar.bz2"
echo "$GVISOR_SHA512  $tarball" | sha512sum -c -
# runsc, its containerd shim, and the gvisor-bin helpers it runs beside it.
tar -xjf "$tarball" -C /usr/local/bin
rm -f "$tarball"
add_handler_v3 runsc io.containerd.runsc.v1
systemctl enable containerd
systemctl restart containerd
check_containerd 2.2.1
check_runc 1.3.4
runsc --version | grep -Fx "runsc version release-$GVISOR_RELEASE"
check_handler runsc
record_packages
