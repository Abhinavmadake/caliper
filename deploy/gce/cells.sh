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
#   cells.sh measure <cell> [image]  reboot, then run the probe through CRI (measure.sh);
#                                    raw probe output on stdout
#   cells.sh packages <cell>         the cell's recorded kernel and package versions
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

# upload <file>...: copy into a fresh directory on the VM and print its path.
upload() {
    local dir
    dir=$(on "mktemp -d /tmp/caliper.XXXXXX")
    gc compute scp --zone "$ZONE" --quiet "$@" "$vm:$dir/" >&2
    echo "$dir"
}

provision() {
    local dir
    dir=$(upload "$here/provision/common.sh" "$here/provision/ubuntu.sh" "$here/provision/$1.sh")
    on "sudo bash $dir/$1.sh && rm -rf $dir"
}

load() {
    local dir
    dir=$(upload "$2")
    on "sudo ctr -n k8s.io images import $dir/$(basename "$2") && rm -rf $dir"
}

# A fresh boot for every measurement: modules autoloaded by an earlier run
# would otherwise be recorded as the node's.
reboot_cell() {
    local before
    before=$(on "cat /proc/sys/kernel/random/boot_id")
    on "sudo systemctl reboot" || true
    for _ in $(seq 60); do
        sleep 5
        after=$(on "cat /proc/sys/kernel/random/boot_id" 2>/dev/null) || continue
        [ -n "$after" ] && [ "$after" != "$before" ] && return 0
    done
    echo "$vm did not come back from reboot" >&2
    return 1
}

measure() {
    local image=${2:-$IMAGE} dir
    reboot_cell
    dir=$(upload "$here/measure.sh")
    on "sudo bash $dir/measure.sh '$image' '$handler'; rc=\$?; rm -rf $dir; exit \$rc"
}

[ $# -ge 2 ] || { sed -n '17,30p' "$0" >&2; exit 2; }
cmd=$1
cell "$2"
case "$cmd" in
    create) create "$2" ;;
    provision) provision "$2" ;;
    load) load "$2" "${3:?archive}" ;;
    measure) measure "$2" "${3:-}" ;;
    packages) on "cat /etc/caliper/packages" ;;
    stop) gc compute instances stop "$vm" --zone "$ZONE" ;;
    start) gc compute instances start "$vm" --zone "$ZONE" ;;
    delete) gc compute instances delete "$vm" --zone "$ZONE" --quiet ;;
    *) echo "unknown command $cmd" >&2; exit 2 ;;
esac
