// Copyright 2026 Abhinav Ajit Madake, Sahil Tatyabhau Waje,
// Ritesh Aresh Saindane, Yogesh Babaji Palve
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! End-to-end tests for the masked and read-only path probe family (#15).

#![cfg(target_os = "linux")]

use serde_json::Value;
use std::collections::BTreeMap;
use std::process::{Command, Stdio};

const PROBE: &str = env!("CARGO_BIN_EXE_caliper-probe");

fn run_probe() -> Value {
    let out = Command::new(PROBE)
        .arg("--run")
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .output()
        .expect("spawn caliper-probe");
    assert!(out.status.success(), "caliper-probe --run failed");
    serde_json::from_slice(&out.stdout).expect("output is JSON")
}

#[test]
fn native_path_probe_verdicts() {
    let doc = run_probe();
    let results = doc["results"].as_array().unwrap();

    let mut map = BTreeMap::new();
    for r in results {
        let id = r["probe_id"].as_str().unwrap();
        map.insert(
            id,
            (r["verdict"].as_str().unwrap(), r["errno"].as_u64().unwrap()),
        );
    }

    // Control probe: /proc/self/status must be reachable procfs (permitted 0)
    let (verdict, errno) = map
        .get("path.control.proc_self_status")
        .copied()
        .expect("path.control.proc_self_status");
    assert_eq!(verdict, "permitted", "control probe verdict");
    assert_eq!(errno, 0, "control probe errno");

    // All path probes reach the kernel (verdict is not killed or timed-out)
    let path_probes = [
        "path.masked.proc_kcore",
        "path.masked.proc_keys",
        "path.masked.proc_latency_stats",
        "path.masked.proc_timer_list",
        "path.masked.proc_timer_stats",
        "path.masked.proc_sched_debug",
        "path.masked.proc_acpi",
        "path.masked.proc_asound",
        "path.masked.proc_scsi",
        "path.masked.sys_firmware",
        "path.masked.sys_powercap",
        "path.readonly.proc_bus",
        "path.readonly.proc_fs",
        "path.readonly.proc_irq",
        "path.readonly.proc_sys",
        "path.readonly.proc_sysrq_trigger",
        "path.control.proc_self_status",
    ];

    for id in path_probes {
        let (verdict, _) = map.get(id).copied().expect(id);
        assert!(
            verdict == "permitted" || verdict == "denied" || verdict == "unimplemented",
            "{id}: unexpected verdict {verdict}"
        );
    }

    // Residual leaks and audit are empty
    let residual = &doc["residual"];
    assert_eq!(
        residual["leaks"].as_array().unwrap(),
        &[] as &[Value],
        "leaks not empty"
    );
    assert_eq!(
        residual["audit"].as_array().unwrap(),
        &[] as &[Value],
        "audit not empty"
    );
}
