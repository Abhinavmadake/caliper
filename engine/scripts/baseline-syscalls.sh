#!/usr/bin/env bash
# Enumerate the engine's own syscall footprint (issue #4).
#
# Runs `caliper-probe --noop` under strace and prints the distinct syscalls
# the process made, sorted. A no-op run exercises exactly the part of the
# engine that is not a probe: musl and Rust std start-up, argument handling,
# exit. That set, plus fork/wait/write/kill for the isolation harness, is
# what the hardened profile must allow for the parent to survive.
#
# Linux only. Usage:  scripts/baseline-syscalls.sh [path/to/caliper-probe]
set -euo pipefail

bin=${1:-target/release/caliper-probe}
[ -x "$bin" ] || { echo "not executable: $bin" >&2; exit 1; }
command -v strace >/dev/null || { echo "strace not installed" >&2; exit 1; }

log=$(mktemp)
trap 'rm -f "$log"' EXIT

# -f follows children (there are none on a no-op run; if one appears, that is
# itself a finding). -qq silences attach/exit noise. Only the syscall name is
# kept: arguments vary per run and are not what this script is for.
strace -f -qq -o "$log" "$bin" --noop
sed -E 's/^[0-9]+ +//; s/\(.*//' "$log" | grep -E '^[a-z_0-9]+$' | sort -u
