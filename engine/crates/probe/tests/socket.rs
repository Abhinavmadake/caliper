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

//! The socket-family and netlink-protocol families (#11), end to end:
//! what holds on every cell regardless of policy. Per-cell expectations
//! (Docker's RuntimeDefault denies AF_VSOCK and CAP-gated families, permits
//! every netlink protocol) are recorded in the PR and the posture, not
//! asserted here, because the test host's policy is not the cell's.

#![cfg(target_os = "linux")]

use std::collections::BTreeMap;
use std::process::{Command, Stdio};

use serde_json::Value;

const PROBE: &str = env!("CARGO_BIN_EXE_caliper-probe");

fn results() -> BTreeMap<String, (String, u64)> {
    let out = Command::new(PROBE)
        .arg("--run")
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .output()
        .expect("spawn caliper-probe");
    assert!(out.status.success(), "caliper-probe --run failed");
    let doc: Value = serde_json::from_slice(&out.stdout).expect("output is JSON");
    doc["results"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            (
                r["probe_id"].as_str().unwrap().to_owned(),
                (
                    r["verdict"].as_str().unwrap().to_owned(),
                    r["errno"].as_u64().unwrap(),
                ),
            )
        })
        .collect()
}

#[test]
fn the_reach_oracles_hold_and_absence_carries_its_errno() {
    let r = results();
    // Reach, with the kernel's own structural answer recorded raw.
    assert_eq!(
        r["socket.family.out_of_range"],
        ("permitted".into(), libc::EAFNOSUPPORT as u64)
    );
    assert_eq!(
        r["netlink.protocol.out_of_range"],
        ("permitted".into(), libc::EPROTONOSUPPORT as u64)
    );
    // The families every kernel builds and every policy permits.
    assert_eq!(r["socket.family.af_unix"], ("permitted".into(), 0));
    assert_eq!(r["netlink.protocol.generic"], ("permitted".into(), 0));

    let mut socket = 0;
    let mut netlink = 0;
    for (id, (verdict, errno)) in &r {
        let absent = if id.starts_with("socket.family.") {
            socket += 1;
            libc::EAFNOSUPPORT
        } else if id.starts_with("netlink.protocol.") {
            netlink += 1;
            libc::EPROTONOSUPPORT
        } else {
            continue;
        };
        // No socket probe forks a grandchild or hangs: three verdicts only.
        assert!(
            matches!(verdict.as_str(), "permitted" | "denied" | "unimplemented"),
            "{id}: {verdict}"
        );
        // `unimplemented` is the family's or protocol's absent errno and
        // nothing else (#8's rule, applied to this family's declarations).
        if verdict == "unimplemented" {
            assert_eq!(*errno, absent as u64, "{id}");
        }
        // A `denied` with the absent errno would mean a probe forgot to
        // declare its kernel dependency.
        if verdict == "denied" {
            assert_ne!(*errno, absent as u64, "{id}: absence recorded as denial");
        }
    }
    assert!(socket >= 20, "{socket} socket-family probes");
    assert!(netlink >= 15, "{netlink} netlink-protocol probes");
}
