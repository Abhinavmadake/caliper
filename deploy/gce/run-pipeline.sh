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

# run-pipeline.sh <cell>: measure, remediate and re-probe one cell.
set -Eeuo pipefail

here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
root=$(cd -- "$here/../.." && pwd)
cells="$here/cells.sh"
project=${CALIPER_GCP_PROJECT:-caliper-ci}
zone=${CALIPER_GCP_ZONE:-asia-south1-a}
cell=${1:-cell2}
# CALIPER_HANDLER selects another of the cell's handlers (cells.sh reads it too).
run=$cell${CALIPER_HANDLER:+-$CALIPER_HANDLER}
out=${CALIPER_PIPELINE_OUT:-$root/fixtures/pipeline/$run}
tier=${CALIPER_POSTURE_TIER:-restricted}
image=${CALIPER_PROBE_IMAGE:-ghcr.io/abhinavmadake/caliper@sha256:e2113465c415c343572c7bd4137df041edb87c202d4728aa670efad2a6093f23}
started=0
spo_created=0

runtime_arch=amd64 oci_arch=SCMP_ARCH_X86_64 distribution="Ubuntu 24.04" runtime_class=runc
case "$cell" in
    cell1) runtime_arch=arm64 oci_arch=SCMP_ARCH_AARCH64 ;;
    cell2 | cell4) ;;
    cell3) distribution="Rocky Linux 9" ;;
    cell5) runtime_class=runsc ;;
    cell6) runtime_class=kata ;;
    *) echo "unknown cell $cell: want cell1 .. cell6" >&2; exit 2 ;;
esac
runtime_class=${CALIPER_HANDLER:-$runtime_class}
if [[ $cell == cell1 && -z ${CALIPER_PROBE_IMAGE:-} ]]; then
    echo "cell1 needs an arm64 image: set CALIPER_PROBE_IMAGE" >&2
    exit 2
fi
vm=caliper-$cell

if ! command -v go >/dev/null 2>&1; then
    echo "Go is required in PATH" >&2
    exit 1
fi

spo_resource=seccompprofiles.security-profiles-operator.x-k8s.io
spo_available=0
if ! command -v kubectl >/dev/null 2>&1; then
    echo "Notice: kubectl is not in PATH; skipping SPO installation check" >&2
elif grep -Fxq "$spo_resource" <<< "$(kubectl api-resources --api-group=security-profiles-operator.x-k8s.io -o name)"; then
    spo_available=1
    for verb in create get watch delete; do
        if [[ $(kubectl auth can-i "$verb" "$spo_resource" 2>/dev/null) != yes ]]; then
            echo "kubectl permission is required: $verb $spo_resource" >&2
            exit 1
        fi
    done
else
    echo "Notice: cluster does not expose the SPO SeccompProfile API; skipping SPO installation check" >&2
fi

cleanup() {
    local status=$?
    trap - EXIT
    if (( spo_created )); then
        kubectl delete -f "$out/pipeline/remediation.spo.yaml" --ignore-not-found=true --wait=true || status=1
    fi
    if (( started )); then
        "$cells" stop "$cell" || status=1
    fi
    exit "$status"
}
trap cleanup EXIT

mkdir -p "$out"
out=$(cd -- "$out" && pwd)
status=$(gcloud compute instances describe "$vm" \
    --project "$project" --zone "$zone" --format='value(status)')
if [[ "$status" != TERMINATED ]]; then
    echo "$vm must be stopped before the pipeline; current status: $status" >&2
    exit 1
fi

# Set before start so the EXIT handler also attempts cleanup if start partially
# succeeds and then reports an error.
started=1
"$cells" start "$cell"

packages=''
for attempt in $(seq 1 12); do
    if packages=$("$cells" packages "$cell" 2>/dev/null); then
        break
    fi
    echo "Waiting for SSH on $vm ($attempt/12)" >&2
    sleep 5
done
if [[ -z "$packages" ]]; then
    echo "could not read package record from $vm" >&2
    exit 1
fi
printf '%s\n' "$packages" | sed 's/[[:space:]]*$//' > "$out/$run.packages"
printf 'probe %s\n' "$image" >> "$out/$run.packages"
kernel=$(awk '$1 == "kernel" { print $2; exit }' "$out/$run.packages")
# The version is the first numeric field: cell3's line ends in a commit hash.
runtime_version=$(awk '$1 == "containerd" && $2 == "containerd" {
    for (i = 3; i <= NF; i++) if ($i ~ /^v?[0-9]+\./) { sub(/^v/, "", $i); print $i; exit } }' "$out/$run.packages")
if [[ -z "$kernel" || -z "$runtime_version" ]]; then
    echo "$cell package record is missing kernel or containerd version" >&2
    exit 1
fi

complete_fingerprint() {
    go run ./cmd/caliper-complete \
        -distribution "$distribution" -runtime containerd \
        -runtime-version "$runtime_version" -runtime-class "$runtime_class" \
        -node-kernel "$kernel"
}

pipeline() {
    go run ./cmd/caliper-pipeline \
        -baseline "$out/$run.json" \
        -runtime-default "$out/containerd-runtime-default.json" \
        -runtime-arch "$runtime_arch" -oci-arch "$oci_arch" \
        -kernel "$kernel" -tier "$tier" -out "$out/pipeline" "$@"
}

"$cells" measure "$cell" "$image" > "$out/$run.raw.json"
"$cells" runtime-default "$cell" "$out/containerd-runtime-default.json"

cd "$root/control"
complete_fingerprint < "$out/$run.raw.json" > "$out/$run.json"
pipeline

if (( spo_available )); then
    kubectl create -f "$out/pipeline/remediation.spo.yaml"
    spo_created=1
    kubectl wait --for='jsonpath={.status.status}=Installed' --timeout=180s \
        -f "$out/pipeline/remediation.spo.yaml"
    kubectl get -f "$out/pipeline/remediation.spo.yaml" -o json \
        > "$out/pipeline/remediation.spo.accepted.json"
fi

cd "$root"
"$cells" measure "$cell" "$image" "$out/pipeline/remediation.localhost.json" \
    > "$out/$run-remediated.raw.json"
cd "$root/control"
complete_fingerprint < "$out/$run-remediated.raw.json" > "$out/$run-remediated.json"
pipeline -verified "$out/$run-remediated.json"

# These repeat the complete fingerprints already stored beside the raw
# measurements, and the report is derivable from those inputs and outputs.
rm -f "$out/pipeline/baseline.fingerprint.json" \
    "$out/pipeline/verified.fingerprint.json" \
    "$out/pipeline/pipeline-report.json"

echo "$run pipeline completed; artifacts: $out"
