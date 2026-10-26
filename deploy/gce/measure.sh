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
#   measure.sh <image> [runtime-handler] [localhost-seccomp-profile] [ground-truth-mode] [corpus-set]
#
# With a profile, the probe runs under it as Kubernetes' Localhost type
# instead of RuntimeDefault (the hardened fixture). A ground-truth mode (none,
# seccomp, capability, paths, apparmor or userns) runs it for #44's
# single-cause environments instead. corpus-set "reduced" runs the reduced
# corpus (#40) instead of the full one. Exit 3 from the probe is a measurement
# with defects: the document is still printed.
set -euo pipefail
export PATH=/usr/local/bin:$PATH

image=$1
handler=${2:-}
profile=${3:-}
ground_truth_mode=${4:-default}
corpus_set=${5:-full}
case "$corpus_set" in
    full) probe_args='["--run"]' ;;
    reduced) probe_args='["--reduced"]' ;;
    *) echo "unknown corpus set: $corpus_set" >&2; exit 2 ;;
esac
work=$(mktemp -d /var/lib/caliper-measure.XXXXXX)
pod=""
restore=()
cleanup() {
    if [ -n "$pod" ]; then
        crictl stopp "$pod" >/dev/null || true
        crictl rmp -f "$pod" >/dev/null || true
    fi
    [ ${#restore[@]} -eq 0 ] || sysctl -qw "${restore[@]}"
    rm -rf "$work"
}
trap cleanup EXIT

# Ground truth where AppArmor must refuse nothing: Ubuntu's restriction on
# unprivileged user namespaces applies even to unconfined tasks, so it is
# lifted for the run. In userns mode the kernel's limit is then the only thing
# that refuses one.
if [ "$ground_truth_mode" = userns ] || [ "$ground_truth_mode" = capability ]; then
    if aa=$(sysctl -n kernel.apparmor_restrict_unprivileged_userns 2>/dev/null); then
        restore+=("kernel.apparmor_restrict_unprivileged_userns=$aa")
        sysctl -qw kernel.apparmor_restrict_unprivileged_userns=0
    fi
fi
if [ "$ground_truth_mode" = userns ]; then
    restore+=("user.max_user_namespaces=$(sysctl -n user.max_user_namespaces)")
    sysctl -qw user.max_user_namespaces=0
fi

install -d -o 65534 -g 65534 "$work/tmp"
install -d "$work/logs"
cat /etc/caliper/packages >&2

# kubelet: pkg/securitycontext/util.go (release-1.36) defaultMaskedPaths and
# defaultReadonlyPaths, including the per-CPU thermal_throttle entries it adds
# when they exist; pid CONTAINER (no shareProcessNamespace); RuntimeDefault
# AppArmor only where AppArmor is on; emptyDir mounts relabelled for SELinux.
python3 - "$work" "$image" "$profile" "$ground_truth_mode" "$probe_args" <<'PY'
import glob, json, os, sys, uuid

work, image, profile, ground_truth_mode = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
probe_args = json.loads(sys.argv[5])
seccomp = {"profile_type": 2, "localhost_ref": profile} if profile else {"profile_type": 0}
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
    "seccomp": seccomp,
    "masked_paths": masked,
    "readonly_paths": readonly,
}
if apparmor:
    security["apparmor"] = {"profile_type": 0}

# Issue #44 ground truth: every control off (root, all capabilities, no
# filter, no LSM profile, no masks) except the one the mode names, so each
# denial in the run has that one cause. "none" leaves everything off, to find
# the denials the kernel makes on its own; "userns" sets the limit on the host
# (below). GCE cells only.
if ground_truth_mode != "default":
    security.update({"run_as_user": {"value": 0}, "capabilities": {"add_capabilities": ["ALL"]},
                     "seccomp": {"profile_type": 1}, "masked_paths": [], "readonly_paths": []})
    if apparmor:
        security["apparmor"] = {"profile_type": 1}
    if ground_truth_mode == "seccomp":
        security["seccomp"] = seccomp
    elif ground_truth_mode == "capability":
        # Unprivileged, so the probes reach their capability checks rather
        # than a root-owned file's permissions (the probe's /tmp is 65534's).
        security["run_as_user"] = {"value": 65534}
        security["capabilities"] = {"drop_capabilities": ["ALL"]}
    elif ground_truth_mode == "paths":
        security["masked_paths"], security["readonly_paths"] = masked, readonly
    elif ground_truth_mode == "apparmor":
        if not apparmor:
            raise SystemExit("ground-truth mode apparmor needs AppArmor on the cell")
        security["apparmor"] = {"profile_type": 0}
    elif ground_truth_mode not in ("none", "userns"):
        raise SystemExit("unknown ground-truth mode: " + ground_truth_mode)
container = {
    "metadata": {"name": "probe"},
    "image": {"image": image},
    "args": probe_args,
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
if [ -z "$profile" ]; then
    python3 - "$work/inspect.json" > "$work/runtime-default.json" <<'PY'
import json, sys
with open(sys.argv[1]) as source:
    runtime_spec = json.load(source)["info"]["runtimeSpec"]
json.dump(runtime_spec.get("linux", {}).get("seccomp", {}), sys.stdout)
PY
    install -m 0644 "$work/runtime-default.json" /var/tmp/caliper-runtime-default.json
fi
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
case "$code" in
    0) ;;
    3) echo "probe exited 3: measured with defects (see the document)" >&2 ;;
    *) echo "probe exited $code" >&2; exit 1 ;;
esac
# CRI log lines are "<time> <stream> <P|F> <text>"; P is a partial line.
awk '$2 == "stdout" { line = $0; sub(/^[^ ]+ [^ ]+ [^ ]+ /, "", line); printf "%s%s", line, ($3 == "F" ? "\n" : "") }' \
    "$(crictl inspect -o go-template --template '{{.status.logPath}}' "$ctr")"
