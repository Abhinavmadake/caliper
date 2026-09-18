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

//! The io_uring family (#12), end to end: the distinction the issue asks
//! for. Either io_uring is denied outright, and every opcode probe says so
//! with the same errno as the reach probe, or the ring is reachable and an
//! opcode is `permitted` or, absent from this kernel, `unimplemented 38`.
//! Which of the two holds depends on the test host's policy; the shape
//! holds on every cell.

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
fn denied_outright_and_opcode_absent_are_different_records() {
    let r = results();
    let (setup_verdict, setup_errno) = &r["io_uring.setup.zero_entries"];
    let opcodes: Vec<_> = r
        .iter()
        .filter(|(id, _)| id.starts_with("io_uring.opcode."))
        .collect();
    assert!(opcodes.len() >= 50, "{} opcode probes", opcodes.len());
    // The control is the first opcode any ring supports.
    assert!(r.contains_key("io_uring.opcode.nop"));

    if setup_verdict == "denied" {
        // Outright: nothing reaches the ring, and every opcode probe
        // carries the same answer the reach probe got.
        for (id, (verdict, errno)) in &opcodes {
            assert_eq!(verdict, "denied", "{id}");
            assert_eq!(errno, setup_errno, "{id}");
        }
    } else {
        // Reachable: the reach probe got its structural EINVAL, the ring
        // could be probed, and the control opcode is supported.
        assert_eq!(
            (setup_verdict.as_str(), *setup_errno),
            ("permitted", libc::EINVAL as u64)
        );
        assert_eq!(r["io_uring.opcode.nop"], ("permitted".into(), 0));
        for (id, (verdict, errno)) in &opcodes {
            match verdict.as_str() {
                "permitted" => assert_eq!(*errno, 0, "{id}"),
                "unimplemented" => assert_eq!(*errno, libc::ENOSYS as u64, "{id}"),
                other => panic!("{id}: {other} {errno} on a reachable ring"),
            }
        }
    }
}
