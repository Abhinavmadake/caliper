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

# Runs on a cell, as root: one probe run through containerd's CRI, built the
# way the kubelet builds deploy/k8s/job.yaml's pod. Raw probe output on
# stdout; what containerd applied, and the cell's packages, on stderr.
#
#   measure.sh <image> [runtime-handler]
set -euo pipefail
export PATH=/usr/local/bin:$PATH

image=$1
handler=${2:-}
work=$(mktemp -d /var/lib/caliper-measure.XXXXXX)
pod=""
cleanup() {
    if [ -n "$pod" ]; then
        crictl stopp "$pod" >/dev/null || true
        crictl rmp -f "$pod" >/dev/null || true
    fi
    rm -rf "$work"
}
trap cleanup EXIT

install -d -o 65534 -g 65534 "$work/tmp"
install -d "$work/logs"
cat /etc/caliper/packages >&2

# kubelet: pkg/securitycontext/util.go (release-1.36) defaultMaskedPaths and
# defaultReadonlyPaths, including the per-CPU thermal_throttle entries it adds
# when they exist; pid CONTAINER (no shareProcessNamespace); RuntimeDefault
# AppArmor only where AppArmor is on; emptyDir mounts relabelled for SELinux.
python3 - "$work" "$image" <<'PY'
import glob, json, os, sys, uuid

work, image = sys.argv[1], sys.argv[2]
masked = ["/proc/asound", "/proc/acpi", "/proc/interrupts", "/proc/kcore", "/proc/keys",
          "/proc/latency_stats", "/proc/timer_list", "/proc/timer_stats", "/proc/sched_debug",
          "/proc/scsi", "/sys/firmware", "/sys/devices/virtual/powercap"]
masked += sorted(glob.glob("/sys/devices/system/cpu/cpu[0-9]*/thermal_throttle"),
                 key=lambda p: int(p.split("/")[5][3:]))
readonly = ["/proc/bus", "/proc/fs", "/proc/irq", "/proc/sys", "/proc/sysrq-trigger"]
namespaces = {"network": 0, "pid": 1, "ipc": 0}
try:
    apparmor = open("/sys/module/apparmor/parameters/enabled").read().strip() == "Y"
except OSError:
    apparmor = False

pod = {
    "metadata": {"name": "caliper-probe", "namespace": "caliper", "uid": str(uuid.uuid4()), "attempt": 0},
    "log_directory": os.path.join(work, "logs"),
    "linux": {"security_context": {"namespace_options": namespaces, "seccomp": {"profile_type": 0}}},
}
security = {
    "namespace_options": namespaces,
    "run_as_user": {"value": 65534},
    "readonly_rootfs": True,
    "no_new_privs": True,
    "capabilities": {"drop_capabilities": ["ALL"]},
    "seccomp": {"profile_type": 0},
    "masked_paths": masked,
    "readonly_paths": readonly,
}
if apparmor:
    security["apparmor"] = {"profile_type": 0}
container = {
    "metadata": {"name": "probe"},
    "image": {"image": image},
    "args": ["--run"],
    "log_path": "probe.log",
    "mounts": [{"container_path": "/tmp", "host_path": os.path.join(work, "tmp"), "selinux_relabel": True}],
    "linux": {"security_context": security},
}
json.dump(pod, open(os.path.join(work, "pod.json"), "w"))
json.dump(container, open(os.path.join(work, "container.json"), "w"))
PY

crictl inspecti "$image" >/dev/null 2>&1 || crictl pull "$image" >&2
runtime=()
[ -n "$handler" ] && runtime=(--runtime "$handler")
pod=$(crictl runp "${runtime[@]}" "$work/pod.json")
ctr=$(crictl create "$pod" "$work/container.json" "$work/pod.json")
crictl start "$ctr" >&2

state=""
for _ in $(seq 300); do
    state=$(crictl inspect -o go-template --template '{{.status.state}}' "$ctr")
    [ "$state" = CONTAINER_EXITED ] && break
    sleep 1
done
crictl inspect "$ctr" > "$work/inspect.json"
python3 - "$work/inspect.json" >&2 <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
s = d["info"]["runtimeSpec"]; p = s["process"]; l = s["linux"]
pid = [n for n in l.get("namespaces", []) if n["type"] == "pid"]
print("applied: seccomp", (l.get("seccomp") or {}).get("defaultAction"),
      "| apparmor", p.get("apparmorProfile"), "| selinux", p.get("selinuxLabel"),
      "| masked", len(l.get("maskedPaths", [])), "readonly", len(l.get("readonlyPaths", [])),
      "| own pid ns", bool(pid) and "path" not in pid[0],
      "| uid", p["user"]["uid"], "| no_new_privs", p.get("noNewPrivileges"))
PY
if [ "$state" != CONTAINER_EXITED ]; then
    echo "probe did not finish within 300 s (state $state)" >&2
    exit 1
fi
code=$(crictl inspect -o go-template --template '{{.status.exitCode}}' "$ctr")
if [ "$code" != 0 ]; then
    echo "probe exited $code" >&2
    exit 1
fi
# CRI log lines are "<time> <stream> <P|F> <text>"; P is a partial line.
awk '$2 == "stdout" { line = $0; sub(/^[^ ]+ [^ ]+ [^ ]+ /, "", line); printf "%s%s", line, ($3 == "F" ? "\n" : "") }' \
    "$(crictl inspect -o go-template --template '{{.status.logPath}}' "$ctr")"
