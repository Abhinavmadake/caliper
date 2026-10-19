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

# Sourced by the Ubuntu 24.04 cells (1, 2, 4, 5, 6).

# Every apt operation reads the archive as it was at this instant, so a cell
# rebuilt later gets the same packages even after noble-updates moves on.
SNAPSHOT=20261016T120000Z

# noble-updates (cells 1, 2, 5, 6) and the noble release pocket (cell 4).
# shellcheck disable=SC2034
UPDATES_CONTAINERD=2.2.1-0ubuntu1~24.04.3
# shellcheck disable=SC2034
UPDATES_RUNC=1.3.4-0ubuntu1~24.04.1
# shellcheck disable=SC2034
RELEASE_CONTAINERD=1.7.12-0ubuntu4
# shellcheck disable=SC2034
RELEASE_RUNC=1.1.12-0ubuntu3

install_ubuntu_runtime() {
    local containerd=$1 runc=$2
    export DEBIAN_FRONTEND=noninteractive
    # Nothing may change the cell between measurements: no unattended
    # upgrades, no new kernel on the next boot.
    systemctl disable --now unattended-upgrades.service apt-daily.timer apt-daily-upgrade.timer
    echo "APT::Snapshot \"$SNAPSHOT\";" > /etc/apt/apt.conf.d/50caliper-snapshot
    apt-get update -q
    apt-get install -y -q --allow-downgrades "containerd=$containerd" "runc=$runc" apparmor curl python3
    # shellcheck disable=SC2046
    apt-mark hold containerd runc apparmor libseccomp2 $(dpkg-query -W -f '${db:Status-Abbrev} ${Package}\n' 'linux-*' | awk '$1 == "ii" { print $2 }')
    aa-status --enabled
}

# containerd merges this over its defaults; only the extra handler is named.
add_handler_v3() {
    local name=$1 type=$2
    mkdir -p /etc/containerd
    cat > /etc/containerd/config.toml <<EOF
version = 3
[plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.$name]
  runtime_type = '$type'
EOF
}
