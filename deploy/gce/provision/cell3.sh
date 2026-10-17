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

# Cell 3: amd64, Rocky Linux 9, containerd 2.2.1 from Docker's repository,
# SELinux enforcing. Moves the LSM (and distribution) against cell 2.
. "$(dirname "$0")/common.sh"
getenforce | grep -qx Enforcing
systemctl disable --now dnf-makecache.timer
dnf install -y -q dnf-plugins-core python3-dnf-plugin-versionlock container-selinux
dnf config-manager --add-repo https://download.docker.com/linux/rhel/docker-ce.repo
dnf install -y -q containerd.io-2.2.1-1.el9
# Hold what defines the cell: runtime, policy, and the kernel it boots.
dnf versionlock add containerd.io container-selinux selinux-policy selinux-policy-targeted libseccomp 'kernel*'
dnf versionlock list | grep -F containerd.io-2.2.1
# containerd.io ships a config that disables CRI; replace it.
cat > /etc/containerd/config.toml <<'TOML'
version = 3
[plugins.'io.containerd.cri.v1.runtime']
  enable_selinux = true
TOML
install_cni
install_crictl
systemctl enable containerd
systemctl restart containerd
check_containerd 2.2.1
# containerd.io bundles its runc.
check_runc 1.3.4
containerd config dump | grep -F 'enable_selinux = true'
record_packages
