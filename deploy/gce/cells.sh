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

# The six cells of proposal §11.1 as Compute Engine VMs (#39).
#
#   cells.sh create  <cell>          VM from a pinned image, then provision
#   cells.sh provision <cell>        re-run the cell's provisioning script
#   cells.sh load    <cell> <tar>    import an image archive (docker save), e.g. arm64 for cell1
#   cells.sh measure <cell> [image]  run the probe through CRI; raw probe output on stdout
#   cells.sh stop    <cell>          stop billing for CPU and memory
#   cells.sh start   <cell>
#   cells.sh delete  <cell>
#
# <cell> is cell1 .. cell6. Every VM is billed while it runs: stop it after use.
set -euo pipefail

PROJECT=${CALIPER_GCP_PROJECT:-caliper-ci}
ZONE=${CALIPER_GCP_ZONE:-asia-south1-a}
# amd64 image published by the cluster-evaluation workflow, pinned by digest.
IMAGE=${CALIPER_PROBE_IMAGE:-ghcr.io/abhinavmadake/caliper@sha256:cbbbb74fda97509a0138633aab981ee3690ee13daeeeb06d27dca5cd16f161f3}
here=$(cd "$(dirname "$0")" && pwd)

# Cells 2, 4, 5 and 6 share one image so only the runtime axis moves.
UBUNTU_AMD64=ubuntu-2404-noble-amd64-v20261016
UBUNTU_ARM64=ubuntu-2404-noble-arm64-v20261016
ROCKY=rocky-linux-9-v20261015

cell() {
    handler=""
    nested=""
    disk=pd-balanced
    case "$1" in
        cell1) machine=c4a-standard-2; image=$UBUNTU_ARM64; family=ubuntu-os-cloud; disk=hyperdisk-balanced ;;
        cell2) machine=e2-standard-2; image=$UBUNTU_AMD64; family=ubuntu-os-cloud ;;
        cell3) machine=e2-standard-2; image=$ROCKY; family=rocky-linux-cloud ;;
        cell4) machine=e2-standard-2; image=$UBUNTU_AMD64; family=ubuntu-os-cloud ;;
        cell5) machine=e2-standard-2; image=$UBUNTU_AMD64; family=ubuntu-os-cloud; handler=runsc ;;
        cell6) machine=n2-standard-2; image=$UBUNTU_AMD64; family=ubuntu-os-cloud; handler=kata; nested=--enable-nested-virtualization ;;
        *) echo "unknown cell $1: want cell1 .. cell6" >&2; exit 2 ;;
    esac
    vm=caliper-$1
}

gc() { gcloud --project "$PROJECT" "$@"; }
on() { gc compute ssh "$vm" --zone "$ZONE" --quiet --command "$1"; }

create() {
    # shellcheck disable=SC2086
    gc compute instances create "$vm" --zone "$ZONE" \
        --machine-type "$machine" $nested \
        --image "$image" --image-project "$family" \
        --boot-disk-size 20GB --boot-disk-type "$disk" \
        --no-service-account --no-scopes \
        --labels caliper-cell="$1"
    for _ in $(seq 30); do on true 2>/dev/null && break; sleep 10; done
    provision "$1"
}

provision() {
    gc compute scp --zone "$ZONE" --quiet "$here/provision/common.sh" "$here/provision/ubuntu.sh" \
        "$here/provision/$1.sh" "$vm:/tmp/"
    on "sudo bash /tmp/$1.sh"
}

load() {
    gc compute scp --zone "$ZONE" --quiet "$2" "$vm:/tmp/caliper-probe.tar"
    on "sudo ctr -n k8s.io images import /tmp/caliper-probe.tar && rm /tmp/caliper-probe.tar"
}

measure() {
    local image=${2:-$IMAGE} runtime=""
    [ -n "$handler" ] && runtime="--runtime $handler"
    on "sudo bash -s" <<EOF
set -euo pipefail
export PATH=/usr/local/bin:\$PATH
uid=\$(cat /proc/sys/kernel/random/uuid)
rm -rf /var/lib/caliper && install -d -o 65534 -g 65534 /var/lib/caliper/tmp
install -d /var/log/caliper
# As the kubelet does: request the AppArmor default only where AppArmor is on.
apparmor=""
grep -qx Y /sys/module/apparmor/parameters/enabled 2>/dev/null && apparmor=', "apparmor": {"profile_type": 0}'
cat > /var/lib/caliper/pod.json <<JSON
{
  "metadata": {"name": "caliper-probe", "namespace": "caliper", "uid": "\$uid", "attempt": 0},
  "log_directory": "/var/log/caliper/\$uid",
  "linux": {"security_context": {"seccomp": {"profile_type": 0}}}
}
JSON
cat > /var/lib/caliper/container.json <<JSON
{
  "metadata": {"name": "probe"},
  "image": {"image": "$image"},
  "args": ["--run"],
  "log_path": "probe.log",
  "mounts": [{"container_path": "/tmp", "host_path": "/var/lib/caliper/tmp"}],
  "linux": {"security_context": {
    "run_as_user": {"value": 65534},
    "readonly_rootfs": true,
    "no_new_privs": true,
    "capabilities": {"drop_capabilities": ["ALL"]},
    "seccomp": {"profile_type": 0}\$apparmor
  }}
}
JSON
echo "node kernel \$(uname -r)" >&2
crictl inspecti "$image" >/dev/null 2>&1 || crictl pull "$image" >&2
pod=\$(crictl runp $runtime /var/lib/caliper/pod.json)
ctr=\$(crictl create "\$pod" /var/lib/caliper/container.json /var/lib/caliper/pod.json)
crictl start "\$ctr" >&2
for _ in \$(seq 120); do
    [ "\$(crictl inspect -o go-template --template '{{.status.state}}' "\$ctr")" = CONTAINER_EXITED ] && break
    sleep 1
done
crictl inspect "\$ctr" | python3 -c 'import json, sys
d = json.load(sys.stdin); s = d["info"]["runtimeSpec"]; p = s["process"]
print("exit", d["status"]["exitCode"], "seccomp", (s["linux"].get("seccomp") or {}).get("defaultAction"),
      "apparmor", p.get("apparmorProfile"), "selinux", p.get("selinuxLabel"), "caps", p.get("capabilities", {}).get("effective"),
      "no_new_privs", p.get("noNewPrivileges"), "user", p["user"]["uid"], file=sys.stderr)' 
# CRI log lines are "<time> <stream> <P|F> <text>"; P is a partial line.
awk '\$2 == "stdout" { line = \$0; sub(/^[^ ]+ [^ ]+ [^ ]+ /, "", line); printf "%s%s", line, (\$3 == "F" ? "\n" : "") }' "\$(crictl inspect -o go-template --template '{{.status.logPath}}' "\$ctr")"
# A Kata sandbox under nested virtualisation can take a minute to stop.
crictl --timeout 3m stopp "\$pod" >/dev/null && crictl rmp "\$pod" >/dev/null
EOF
}

[ $# -ge 2 ] || { sed -n '17,27p' "$0" >&2; exit 2; }
cmd=$1
cell "$2"
case "$cmd" in
    create) create "$2" ;;
    provision) provision "$2" ;;
    load) load "$2" "${3:?archive}" ;;
    measure) measure "$2" "${3:-}" ;;
    stop) gc compute instances stop "$vm" --zone "$ZONE" ;;
    start) gc compute instances start "$vm" --zone "$ZONE" ;;
    delete) gc compute instances delete "$vm" --zone "$ZONE" --quiet ;;
    *) echo "unknown command $cmd" >&2; exit 2 ;;
esac
