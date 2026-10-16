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
# crictl, CNI, and the checks that make provisioning fail on a wrong version.

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

install_crictl() {
    curl -fsSL "https://github.com/kubernetes-sigs/cri-tools/releases/download/$CRICTL_VERSION/crictl-$CRICTL_VERSION-linux-$(goarch).tar.gz" \
        | tar -xz -C /usr/local/bin crictl
    cat > /etc/crictl.yaml <<'EOF'
runtime-endpoint: unix:///run/containerd/containerd.sock
image-endpoint: unix:///run/containerd/containerd.sock
EOF
}

# A pod gets its own network namespace, as under Kubernetes, so CNI is needed.
install_cni() {
    mkdir -p /opt/cni/bin /etc/cni/net.d
    curl -fsSL "https://github.com/containernetworking/plugins/releases/download/$CNI_VERSION/cni-plugins-linux-$(goarch)-$CNI_VERSION.tgz" \
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
