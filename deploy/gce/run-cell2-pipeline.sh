#!/usr/bin/env bash
set -Eeuo pipefail

here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
root=$(cd -- "$here/../.." && pwd)
cells="$here/cells.sh"
project=${CALIPER_GCP_PROJECT:-caliper-ci}
zone=${CALIPER_GCP_ZONE:-asia-south1-a}
out=${CALIPER_PIPELINE_OUT:-$root/artifacts}
tier=${CALIPER_POSTURE_TIER:-untrusted-multi-tenant}
started=0
if command -v go >/dev/null 2>&1; then
    go_tool=go
elif command -v go.exe >/dev/null 2>&1; then
    go_tool=go.exe
else
    echo "Go is required (go or go.exe must be available in PATH)" >&2
    exit 1
fi

cleanup() {
    local status=$?
    trap - EXIT
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
kernel=$(awk '$1 == "kernel" { print $2; exit }' "$out/cell2.packages")
runtime_version=$(awk '$1 == "containerd" && $2 == "containerd" { print $NF; exit }' "$out/cell2.packages")
if [[ -z "$kernel" || -z "$runtime_version" ]]; then
    echo "cell2 package record is missing kernel or containerd version" >&2
    exit 1
fi

"$cells" measure cell2 > "$out/cell2.raw.json"
"$cells" runtime-default cell2 "$out/containerd-runtime-default.json"

cd "$root/control"
control_out=$(realpath --relative-to="$root/control" "$out")
"$go_tool" run ./cmd/caliper-complete \
    -distribution "Ubuntu 24.04" -runtime containerd \
    -runtime-version "$runtime_version" -runtime-class runc \
    -node-kernel "$kernel" \
    < "$out/cell2.raw.json" > "$out/cell2.json"

"$go_tool" run ./cmd/caliper-pipeline \
    -baseline "$control_out/cell2.json" \
    -runtime-default "$control_out/containerd-runtime-default.json" \
    -runtime-arch amd64 -oci-arch SCMP_ARCH_X86_64 \
    -kernel "$kernel" -tier "$tier" -out "$control_out/pipeline"

cd "$root"
"$cells" measure cell2 "" "$out/pipeline/remediation.localhost.json" \
    > "$out/cell2-remediated.raw.json"
cd "$root/control"
"$go_tool" run ./cmd/caliper-complete \
    -distribution "Ubuntu 24.04" -runtime containerd \
    -runtime-version "$runtime_version" -runtime-class runc \
    -node-kernel "$kernel" \
    < "$out/cell2-remediated.raw.json" > "$out/cell2-remediated.json"

"$go_tool" run ./cmd/caliper-pipeline \
    -baseline "$control_out/cell2.json" \
    -verified "$control_out/cell2-remediated.json" \
    -runtime-default "$control_out/containerd-runtime-default.json" \
    -runtime-arch amd64 -oci-arch SCMP_ARCH_X86_64 \
    -kernel "$kernel" -tier "$tier" -out "$control_out/pipeline"

echo "Cell2 pipeline completed; artifacts: $out"
