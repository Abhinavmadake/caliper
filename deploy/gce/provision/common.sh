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

# Sourced by the cell scripts. Everything a cell needs besides its runtime:
# crictl, CNI, the checks that make provisioning fail on a wrong version, and
# the package record kept in /etc/caliper/packages.

set -euxo pipefail

CRICTL_VERSION=v1.37.0
CNI_VERSION=v1.9.1

goarch() {
    case "$(uname -m)" in
        x86_64) echo amd64 ;;
        aarch64) echo arm64 ;;
        *) echo "unsupported $(uname -m)" >&2; exit 1 ;;
    esac
}

# fetch <url> <sha256>: the download, verified, on stdout.
fetch() {
    local file
    file=$(mktemp)
    curl -fsSL -o "$file" "$1"
    echo "$2  $file" | sha256sum -c - >&2
    cat "$file"
    rm -f "$file"
}

install_crictl() {
    local sha
    case "$(goarch)" in
        amd64) sha=67c983ee8a6bbce73d39a186e633c5fe4f8a70e62171ac3bd92a9c1b2c601670 ;;
        arm64) sha=c9dfdf9ebc353a0027c88622206a5e90ee6f0e78cfabf1a9ef4dc575298fd555 ;;
    esac
    fetch "https://github.com/kubernetes-sigs/cri-tools/releases/download/$CRICTL_VERSION/crictl-$CRICTL_VERSION-linux-$(goarch).tar.gz" "$sha" \
        | tar -xz -C /usr/local/bin crictl
    # crictl's own default is 2 s; a Kata sandbox under nested virtualisation
    # takes far longer to start and stop.
    cat > /etc/crictl.yaml <<'EOF'
runtime-endpoint: unix:///run/containerd/containerd.sock
image-endpoint: unix:///run/containerd/containerd.sock
timeout: 180
EOF
}

# A pod gets its own network namespace, as under Kubernetes, so CNI is needed.
install_cni() {
    local sha
    case "$(goarch)" in
        amd64) sha=b98f74a0f8522f0a83867178729c1aa70f2158f90c45a2ca8fa791db1c76b303 ;;
        arm64) sha=56171987d3947707c3563db2f4001bccaf50fd63468611b9f3cbecb1375ee7ec ;;
    esac
    mkdir -p /opt/cni/bin /etc/cni/net.d
    fetch "https://github.com/containernetworking/plugins/releases/download/$CNI_VERSION/cni-plugins-linux-$(goarch)-$CNI_VERSION.tgz" "$sha" \
        | tar -xz -C /opt/cni/bin
    cat > /etc/cni/net.d/10-caliper.conflist <<'EOF'
{
  "cniVersion": "1.0.0",
  "name": "caliper",
  "plugins": [
    {
      "type": "bridge",
      "bridge": "cni0",
      "isGateway": true,
      "ipMasq": true,
      "ipam": {"type": "host-local", "ranges": [[{"subnet": "10.88.0.0/16"}]], "routes": [{"dst": "0.0.0.0/0"}]}
    },
    {"type": "loopback"}
  ]
}
EOF
}

# The binary on PATH and the running daemon must both be the pinned one
# (#90: a second containerd earlier on PATH would measure another profile).
version_is() {
    grep -E "(^|[ v])${1//./\\.}([ +~-]|$)"
}

check_containerd() {
    [ "$(readlink -f "$(command -v containerd)")" = /usr/bin/containerd ]
    containerd --version | version_is "$1"
    ctr version | sed -n '/^Server:/,$p' | grep Version: | version_is "$1"
}

check_runc() {
    case "$(readlink -f "$(command -v runc)")" in /usr/bin/runc | /usr/sbin/runc) ;; *) return 1 ;; esac
    runc --version | head -1 | version_is "$1"
}

check_handler() {
    crictl info | grep -F "\"$1\""
}

# What defines the cell besides the runtime, for the record and for measure.
record_packages() {
    mkdir -p /etc/caliper
    {
        echo "kernel $(uname -r)"
        echo "containerd $(containerd --version)"
        echo "runc $(runc --version | head -1)"
        if command -v dpkg-query >/dev/null; then
            dpkg-query -W -f '${Package} ${Version}\n' containerd runc apparmor libseccomp2 'linux-image-*' 2>/dev/null | grep -v ' $'
        else
            rpm -q containerd.io kernel selinux-policy-targeted container-selinux libseccomp
        fi
        for f in /usr/local/bin/runsc /opt/kata/bin/kata-runtime; do
            if [ -x "$f" ]; then "$f" --version | head -1; fi
        done
    } > /etc/caliper/packages
    cat /etc/caliper/packages
}
