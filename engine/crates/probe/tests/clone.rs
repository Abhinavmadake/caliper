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

//! End-to-end tests for the clone and unshare flags probe family (#14).

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
fn native_unprivileged_clone_and_unshare_verdicts() {
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

    // 1. Unprivileged userns / unprivileged clone flags:
    // permitted (errno 0) or denied EACCES/EPERM depending on host userns sysctl/AppArmor.
    let unprivileged_flags = [
        "unshare.flags.newuser",
        "unshare.flags.newuser_newnet",
        "clone.flags.newuser",
        "clone.flags.newuser_newnet",
        "clone.flags.newtime",
    ];
    for id in unprivileged_flags {
        let (verdict, errno) = map.get(id).copied().expect(id);
        assert!(
            (verdict == "permitted" && errno == 0)
                || (verdict == "denied"
                    && (errno == libc::EACCES as u64 || errno == libc::EPERM as u64)),
            "{id}: unexpected verdict {verdict} / errno {errno}"
        );
    }

    // 2. Privileged flags without CAP_SYS_ADMIN answer denied with EPERM (1).
    let sysadmin_flags = [
        "unshare.flags.newns",
        "unshare.flags.newnet",
        "unshare.flags.newpid",
        "unshare.flags.newipc",
        "unshare.flags.newuts",
        "unshare.flags.newcgroup",
        "unshare.flags.newtime",
        "clone.flags.newns",
        "clone.flags.newnet",
        "clone.flags.newpid",
        "clone.flags.newipc",
        "clone.flags.newuts",
        "clone.flags.newcgroup",
    ];

    for id in sysadmin_flags {
        let (verdict, errno) = map.get(id).copied().expect(id);
        assert_eq!(verdict, "denied", "{id}");
        assert_eq!(errno, libc::EPERM as u64, "{id}");
    }

    // 3. Side effects residual audit and leaks are empty.
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
