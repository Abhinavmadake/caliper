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

set -Eeuo pipefail

here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
root=$(cd -- "$here/../.." && pwd)
cells="$here/cells.sh"
project=${CALIPER_GCP_PROJECT:-caliper-ci}
zone=${CALIPER_GCP_ZONE:-asia-south1-a}
out=${CALIPER_PIPELINE_OUT:-$root/fixtures/pipeline/cell2}
tier=${CALIPER_POSTURE_TIER:-restricted}
started=0
spo_created=0
if ! command -v go >/dev/null 2>&1; then
    echo "Go is required in PATH" >&2
    exit 1
fi
if ! command -v kubectl >/dev/null 2>&1; then
    echo "kubectl is required in PATH to validate the SPO profile" >&2
    exit 1
fi

spo_resource=seccompprofiles.security-profiles-operator.x-k8s.io
if ! kubectl api-resources --api-group=security-profiles-operator.x-k8s.io -o name \
    | grep -Fxq "$spo_resource"; then
    echo "The cluster does not expose the SPO SeccompProfile API" >&2
    exit 1
fi
for verb in create get watch delete; do
    if [[ $(kubectl auth can-i "$verb" "$spo_resource" 2>/dev/null) != yes ]]; then
        echo "kubectl permission is required: $verb $spo_resource" >&2
        exit 1
    fi
done

cleanup() {
    local status=$?
    trap - EXIT
    if (( spo_created )); then
        kubectl delete -f "$out/pipeline/remediation.spo.yaml" --ignore-not-found=true --wait=true || status=1
    fi
    if (( started )); then
        "$cells" stop cell2 || status=1
    fi
    exit "$status"
}
trap cleanup EXIT

mkdir -p "$out"
out=$(cd -- "$out" && pwd)
status=$(gcloud compute instances describe caliper-cell2 \
    --project "$project" --zone "$zone" --format='value(status)')
if [[ "$status" != TERMINATED ]]; then
    echo "caliper-cell2 must be stopped before the pipeline; current status: $status" >&2
    exit 1
fi

# Set before start so the EXIT handler also attempts cleanup if start partially
# succeeds and then reports an error.
started=1
"$cells" start cell2

packages=''
for attempt in $(seq 1 12); do
    if packages=$("$cells" packages cell2 2>/dev/null); then
        break
    fi
    echo "Waiting for SSH on caliper-cell2 ($attempt/12)" >&2
    sleep 5
done
if [[ -z "$packages" ]]; then
    echo "could not read package record from caliper-cell2" >&2
    exit 1
fi
printf '%s\n' "$packages" | sed 's/[[:space:]]*$//' > "$out/cell2.packages"
printf 'probe %s\n' "${CALIPER_PROBE_IMAGE:-ghcr.io/abhinavmadake/caliper@sha256:9be163f1b987f8563f9d71114d6a025d9335b9627cdafc4676da2b327da3f969}" >> "$out/cell2.packages"
kernel=$(awk '$1 == "kernel" { print $2; exit }' "$out/cell2.packages")
runtime_version=$(awk '$1 == "containerd" && $2 == "containerd" { print $NF; exit }' "$out/cell2.packages")
if [[ -z "$kernel" || -z "$runtime_version" ]]; then
    echo "cell2 package record is missing kernel or containerd version" >&2
    exit 1
fi

"$cells" measure cell2 > "$out/cell2.raw.json"
"$cells" runtime-default cell2 "$out/containerd-runtime-default.json"

cd "$root/control"
go run ./cmd/caliper-complete \
    -distribution "Ubuntu 24.04" -runtime containerd \
    -runtime-version "$runtime_version" -runtime-class runc \
    -node-kernel "$kernel" \
    < "$out/cell2.raw.json" > "$out/cell2.json"

go run ./cmd/caliper-pipeline \
    -baseline "$out/cell2.json" \
    -runtime-default "$out/containerd-runtime-default.json" \
    -runtime-arch amd64 -oci-arch SCMP_ARCH_X86_64 \
    -kernel "$kernel" -tier "$tier" -out "$out/pipeline"

kubectl create -f "$out/pipeline/remediation.spo.yaml"
spo_created=1
kubectl wait --for='jsonpath={.status.status}=Installed' --timeout=180s \
    -f "$out/pipeline/remediation.spo.yaml"
kubectl get -f "$out/pipeline/remediation.spo.yaml" -o json \
    > "$out/pipeline/remediation.spo.accepted.json"

cd "$root"
"$cells" measure cell2 "" "$out/pipeline/remediation.localhost.json" \
    > "$out/cell2-remediated.raw.json"
cd "$root/control"
go run ./cmd/caliper-complete \
    -distribution "Ubuntu 24.04" -runtime containerd \
    -runtime-version "$runtime_version" -runtime-class runc \
    -node-kernel "$kernel" \
    < "$out/cell2-remediated.raw.json" > "$out/cell2-remediated.json"

go run ./cmd/caliper-pipeline \
    -baseline "$out/cell2.json" \
    -verified "$out/cell2-remediated.json" \
    -runtime-default "$out/containerd-runtime-default.json" \
    -runtime-arch amd64 -oci-arch SCMP_ARCH_X86_64 \
    -kernel "$kernel" -tier "$tier" -out "$out/pipeline"

# These repeat the complete fingerprints already stored beside the raw
# measurements, and the report is derivable from those inputs and outputs.
rm -f "$out/pipeline/baseline.fingerprint.json" \
    "$out/pipeline/verified.fingerprint.json" \
    "$out/pipeline/pipeline-report.json"

echo "Cell2 pipeline completed; artifacts: $out"
